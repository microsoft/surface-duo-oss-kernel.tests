#!/bin/bash
#
# Copyright (C) 2018 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

set -e
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)

# Make sure we're in C locale so build inside chroot does not complain
# about missing files
unset LANG LANGUAGE \
  LC_ADDRESS LC_ALL LC_COLLATE LC_CTYPE LC_IDENTIFICATION LC_MEASUREMENT \
  LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE LC_TIME
export LC_ALL=C

usage() {
  echo -n "usage: $0 [-h] [-s bullseye|bullseye-cuttlefish] "
  echo -n "[-a i386|amd64|armhf|arm64] "
  echo -n "[-m http://mirror/debian] [-n rootfs] [-r initrd]"
  exit 1
}

mirror=http://ftp.debian.org/debian
suite=bullseye
arch=amd64

ramdisk=
rootfs=

while getopts ":hs:a:m:n:r:" opt; do
  case "${opt}" in
    h)
      usage
      ;;
    s)
      if [[ "${OPTARG%-*}" != "bullseye" ]]; then
        echo "Invalid suite: ${OPTARG}" >&2
        usage
      fi
      suite="${OPTARG}"
      ;;
    a)
      case "${OPTARG}" in
        i386|amd64|armhf|arm64)
          arch="${OPTARG}"
          ;;
        *)
          echo "Invalid arch: ${OPTARG}" >&2
          usage
          ;;
      esac
      ;;
    m)
      mirror="${OPTARG}"
      ;;
    n)
      rootfs="${OPTARG}"
      ;;
    r)
      ramdisk="${OPTARG}"
      ;;
    \?)
      echo "Invalid option: ${OPTARG}" >&2
      usage
      ;;
    :)
      echo "Invalid option: ${OPTARG} requires an argument" >&2
      usage
      ;;
  esac
done

if [[ -z "${rootfs}" ]]; then
  rootfs="rootfs.${arch}.${suite}.$(date +%Y%m%d)"
fi
rootfs=$(realpath "${rootfs}")

if [[ -z "${ramdisk}" ]]; then
  ramdisk="initrd.${arch}.${suite}.$(date +%Y%m%d)"
fi
ramdisk=$(realpath "${ramdisk}")

# Sometimes it isn't obvious when the script fails
failure() {
  echo "Filesystem generation process failed." >&2
  rm -f "${rootfs}" "${ramdisk}"
}
trap failure ERR

# Import the package list for this release
packages=$(cpp "${SCRIPT_DIR}/rootfs/${suite}.list" | grep -v "^#" | xargs | tr -s ' ' ',')

# For the debootstrap intermediates
tmpdir=$(mktemp -d)
tmpdir_remove() {
  echo "Removing temporary files.." >&2
  sudo rm -rf "${tmpdir}"
}
trap tmpdir_remove EXIT

workdir="${tmpdir}/_"
mkdir "${workdir}"
chmod 0755 "${workdir}"
sudo chown root:root "${workdir}"

# Run the debootstrap first
cd "${workdir}"
sudo debootstrap --arch="${arch}" --variant=minbase --include="${packages}" \
                 --foreign "${suite%-*}" . "${mirror}"

# Copy some bootstrapping scripts into the rootfs
sudo cp -a "${SCRIPT_DIR}"/rootfs/*.sh root/
sudo cp -a "${SCRIPT_DIR}"/rootfs/net_test.sh sbin/net_test.sh
sudo chown -R root:root root/ sbin/net_test.sh

# Create /host, for the pivot_root and 9p mount use cases
sudo mkdir host

sudo chroot . root/stage2.sh
sudo chroot . root/${suite}.sh
raw_initrd="${PWD}"/boot/initrd.img

# Workarounds for bugs in the debootstrap suite scripts
for mount in $(cat /proc/mounts | cut -d' ' -f2 | grep -e "^${workdir}"); do
  echo "Unmounting mountpoint ${mount}.." >&2
  sudo umount "${mount}"
done

# Leave the workdir, to process the initrd
cd -

# New workdir for the initrd extraction
workdir="${tmpdir}/initrd"
mkdir "${workdir}"
chmod 0755 "${workdir}"
sudo chown root:root "${workdir}"

# Change into workdir to repack initramfs
cd "${workdir}"

# Process the initrd to remove kernel-specific metadata
lz4 -lcd "${raw_initrd}" | sudo cpio -idum
sudo rm -f "${raw_initrd}"
sudo rm -rf usr/lib/modules
sudo mkdir -p usr/lib/modules

# Debian symlinks /usr/lib to /lib, but we'd prefer the other way around
# so that it more closely matches what happens in Android initramfs images.
# This enables 'cat ramdiskA.img ramdiskB.img >ramdiskC.img' to "just work".
sudo rm -f lib
sudo mv usr/lib lib
sudo ln -s /lib usr/lib

# Repack the ramdisk to the final output
find * | sudo cpio -H newc -o --quiet | lz4 -lc9 >"${ramdisk}"

# Leave the workdir, to build the filesystem
workdir="${tmpdir}/_"
cd -

# For the final image mount
mount=$(mktemp -d)
mount_remove() {
  rmdir "${mount}"
  tmpdir_remove
}
trap mount_remove EXIT

# Create a 1G empty ext3 filesystem
truncate -s 1G "${rootfs}"
mke2fs -F -t ext3 -L ROOT "${rootfs}"

# Mount the new filesystem locally
sudo mount -o loop -t ext3 "${rootfs}" "${mount}"
image_unmount() {
  sudo umount "${mount}"
  mount_remove
}
trap image_unmount EXIT

# Copy the patched debootstrap results into the new filesystem
sudo cp -a "${workdir}"/* "${mount}"

# Fill the rest of the space with zeroes, to optimize compression
sudo dd if=/dev/zero of="${mount}/sparse" bs=1M 2>/dev/null || true
sudo rm -f "${mount}/sparse"

echo "Debian ${suite} for ${arch} filesystem generated at '${rootfs}'."
echo "Initial ramdisk generated at '${ramdisk}'."
