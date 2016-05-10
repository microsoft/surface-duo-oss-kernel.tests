#!/usr/bin/python
#
# Copyright 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for csocket."""

import socket
import unittest

import csocket


class CsocketTest(unittest.TestCase):

  def CheckRecvfrom(self, family, addr):
    s = socket.socket(family, socket.SOCK_DGRAM, 0)
    s.bind((addr, 0))

    addr = s.getsockname()
    sockaddr = csocket.Sockaddr(addr)
    s.sendto("foo", addr)
    data, addr = csocket.Recvfrom(s, 4096, 0)
    self.assertEqual("foo", data)
    self.assertEqual(sockaddr, addr)

    s.close()

  def testRecvfrom(self):
    self.CheckRecvfrom(socket.AF_INET, "127.0.0.1")
    self.CheckRecvfrom(socket.AF_INET6, "::1")


if __name__ == "__main__":
  unittest.main()
