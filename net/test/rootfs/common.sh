#!/bin/sh
#
# Copyright (C) 2021 The Android Open Source Project
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

# $1 - Suite name for apt sources
update_apt_sources() {
  # Add the needed debian sources
  cat >/etc/apt/sources.list <<EOF
deb http://ftp.debian.org/debian bullseye main
deb-src http://ftp.debian.org/debian bullseye main
EOF

  # Disable the automatic installation of recommended packages
  cat >/etc/apt/apt.conf.d/90recommends <<EOF
APT::Install-Recommends "0";
EOF

  # On the ARM64, allow packages from AMD64 to be installed
  dpkg --add-architecture amd64

  # Update for the above changes
  apt-get update
}

# $1 - Output file for currently installed packages
get_installed_packages() {
  LANG=C dpkg --get-selections | sort
}

# $1 - File containing package selections to restore to
# $2 - File containing currently installed packages list
remove_installed_packages() {
  apt-get purge --allow-remove-essential -y \
    $(comm -3 "$1" "$2" | sed -e 's,install,,' -e 's,\t,,' | xargs)
  rm -f "$1" "$2"
}

setup_static_networking() {
  # Permanently update the resolv.conf with the Google DNS servers
  echo "nameserver 8.8.8.8"  >/etc/resolv.conf
  echo "nameserver 8.8.4.4" >>/etc/resolv.conf
}

# $* - One or more device names for getty spawns
create_systemd_getty_symlinks() {
  for device in $*; do
    ln -s /lib/systemd/system/serial-getty\@.service \
      /etc/systemd/system/getty.target.wants/serial-getty\@"${device}".service
  done
}

cleanup() {
  # Prevents systemd boot issues with read-only rootfs
  mkdir -p /var/lib/systemd/{coredump,linger,rfkill,timesync}
  chown systemd-timesync:systemd-timesync /var/lib/systemd/timesync

  # Miscellaneous cleanup
  rm -rf /var/lib/apt/lists/* || true
  rm -f /root/* || true
  apt-get clean
}
