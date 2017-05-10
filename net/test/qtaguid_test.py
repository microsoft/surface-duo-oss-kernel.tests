#!/usr/bin/python
#
# Copyright 2017 The Android Open Source Project
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

"""Unit tests for xt_qtaguid."""

import errno
from socket import *  # pylint: disable=wildcard-import
import unittest
import os
import csocket
import net_test

CTRL_PROCPATH = "/proc/net/xt_qtaguid/ctrl"

class QtaguidTest(net_test.NetworkTest):

  def WriteToCtrl(self, command):
    ctrl_file = open(CTRL_PROCPATH, 'w')
    ctrl_file.write(command)
    ctrl_file.close()

  def CheckTag(self, tag, uid):
    for line in open(CTRL_PROCPATH, 'r').readlines():
      if "tag=0x%x (uid=%d)" % ((tag|uid), uid) in line:
        return True
    return False

  def SetIptablesRule(self, version, is_add, is_gid, my_id):
    add_del = "-A" if is_add else "-D"
    uid_gid = "--gid-owner" if is_gid else "--uid-owner"
    args = "%s OUTPUT -m owner %s %d -j DROP" % (add_del, uid_gid, my_id)
    self.assertFalse(net_test.RunIptablesCommand(version, args))

  def CheckSocketOutput(self, version, is_gid):
    myId = os.getgid() if is_gid else os.getuid()
    self.SetIptablesRule(version, True, is_gid, myId);
    family = {4: AF_INET, 6: AF_INET6}[version]
    s = socket(family, SOCK_DGRAM, 0)
    addr = {4: "127.0.0.1", 6: "::1"}[version]
    s.bind((addr, 0))
    addr = s.getsockname()
    self.assertRaisesErrno(errno.EPERM, s.sendto, "foo", addr)
    self.SetIptablesRule(version, False, is_gid, myId)
    s.sendto("foo", addr)
    data, sockaddr = s.recvfrom(4096)
    self.assertEqual("foo", data)
    self.assertEqual(sockaddr, addr)

  def testCloseWithoutUntag(self):
    self.dev_file = open("/dev/xt_qtaguid", "r");
    sk = socket(AF_INET, SOCK_DGRAM, 0)
    uid = os.getuid()
    tag = 0xff00ff00 << 32
    command =  "t %d %d %d" % (sk.fileno(), tag, uid)
    self.WriteToCtrl(command)
    self.assertTrue(self.CheckTag(tag, uid))
    sk.close();
    self.assertFalse(self.CheckTag(tag, uid))
    self.dev_file.close();

  def testTagWithoutDeviceOpen(self):
    sk = socket(AF_INET, SOCK_DGRAM, 0)
    uid = os.getuid()
    tag = 0xff00ff00 << 32
    command = "t %d %d %d" % (sk.fileno(), tag, uid)
    self.WriteToCtrl(command)
    self.assertTrue(self.CheckTag(tag, uid))
    self.dev_file = open("/dev/xt_qtaguid", "r")
    sk.close()
    self.assertFalse(self.CheckTag(tag, uid))
    self.dev_file.close();

  def testUidGidMatch(self):
    self.CheckSocketOutput(4, False)
    self.CheckSocketOutput(6, False)
    self.CheckSocketOutput(4, True)
    self.CheckSocketOutput(6, True)

  @unittest.skip("does not pass on current kernels")
  def testCheckNotMatchGid(self):
    self.assertIn("match_no_sk_gid", open(CTRL_PROCPATH, 'r').read())


if __name__ == "__main__":
  unittest.main()
