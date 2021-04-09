#!/bin/bash
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

. $SCRIPT_DIR/common.sh

iptables=iptables-1.8.7
debian_iptables=1.8.7-1

setup_and_build_iptables() {
  # Install everything needed from bullseye to build iptables
  apt-get install -y \
    build-essential \
    autoconf \
    automake \
    bison \
    debhelper \
    devscripts \
    fakeroot \
    flex \
    libmnl-dev \
    libnetfilter-conntrack-dev \
    libnfnetlink-dev \
    libnftnl-dev \
    libtool

  # Construct the iptables source package to build
  mkdir -p /usr/src/$iptables

  cd /usr/src/$iptables
    # Download a specific revision of iptables from AOSP
    wget -qO - \
      https://android.googlesource.com/platform/external/iptables/+archive/master.tar.gz | \
      tar -zxf -
    # Download a compatible 'debian' overlay from Debian salsa
    # We don't want all of the sources, just the Debian modifications
    # NOTE: This will only work if Android always uses a version of iptables
    #       that exists for Debian as well.
    debian_iptables_dir=pkg-iptables-debian-$debian_iptables
    wget -qO - \
      https://salsa.debian.org/pkg-netfilter-team/pkg-iptables/-/archive/debian/$debian_iptables/$debian_iptables_dir.tar.gz | \
      tar --strip-components 1 -zxf - \
      $debian_iptables_dir/debian
  cd -

  cd /usr/src
    # Generate a source package to leave in the filesystem. This is done for
    # license compliance and build reproducibility.
    tar --exclude=debian -cf - $iptables | \
      xz -9 >$(echo $iptables | tr -s '-' '_').orig.tar.xz
  cd -

  cd /usr/src/$iptables
    # Build debian packages from the integrated iptables source
    dpkg-buildpackage -F -d -us -uc
  cd -
}

install_and_cleanup_iptables() {
  cd /usr/src
    # Find any packages generated, resolve to the debian package name, then
    # exclude any compat, header or symbol packages
    packages=$(find -maxdepth 1 -name '*.deb' | colrm 1 2 | cut -d'_' -f1 |
               grep -ve '-compat$\|-dbg$\|-dbgsym$\|-dev$' | xargs)
    # Install the patched iptables packages, and 'hold' then so
    # "apt-get dist-upgrade" doesn't replace them
    apt-get install --allow-downgrades -y -f \
      $(for package in $packages; do echo ./${package}_*.deb; done | xargs)
    for package in $packages; do
      echo "$package hold" | LANG=C dpkg --set-selections
    done

    # Tidy up the mess we left behind, leaving just the source tarballs
    rm -rf $iptables *.{buildinfo,changes,deb,dsc}
  cd -
}

bullseye_cleanup() {
  cleanup
}
