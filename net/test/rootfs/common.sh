#!/bin/sh
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

chroot_sanity_check() {
  if [ ! -f /var/log/bootstrap.log ]; then
    echo "Do not run this script directly!"
    echo "This is supposed to be run from inside a debootstrap chroot!"
    echo "Aborting."
    exit 1
  fi
}

chroot_cleanup() {
  # Remove contaminants coming from the debootstrap process
  echo "nameserver 127.0.0.1" >/etc/resolv.conf

  # Disable the root password
  passwd -d root

  # Clean up any junk created by the imaging process
  rm -rf /root/*
}
