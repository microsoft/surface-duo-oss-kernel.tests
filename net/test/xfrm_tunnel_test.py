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

# pylint: disable=g-bad-todo,g-bad-file-header,wildcard-import
from errno import *  # pylint: disable=wildcard-import
from socket import *  # pylint: disable=wildcard-import

import struct
import unittest

import iproute
import multinetwork_base
import net_test
import xfrm
import xfrm_base

# Parameters to Set up VTI as a special network
_VTI_NETID = 50
_VTI_IFNAME = "test_vti"

_TEST_OUT_SPI = 0x1234
_TEST_IN_SPI = 0x5678

_TEST_OKEY = _TEST_OUT_SPI + _VTI_NETID
_TEST_IKEY = _TEST_IN_SPI + _VTI_NETID


class XfrmTunnelTest(xfrm_base.XfrmBaseTest):

  def setUp(self):
    super(XfrmTunnelTest, self).setUp()
    # if the hard-coded netids are redefined this will catch the error
    self.assertNotIn(_VTI_NETID, self.NETIDS,
                     "VTI netid %d already in use" % _VTI_NETID)
    self.iproute = iproute.IPRoute()
    self._QuietDeleteLink(_VTI_IFNAME)

  def tearDown(self):
    super(XfrmTunnelTest, self).tearDown()
    self._QuietDeleteLink(_VTI_IFNAME)

  @staticmethod
  def _GetLocalInnerAddress(version):
    return {4: "10.16.5.15", 6: "2001:db8:1::1"}[version]

  @staticmethod
  def _GetRemoteInnerAddress(version):
    return {4: "10.16.5.20", 6: "2001:db8:2::1"}[version]

  def _GetRemoteOuterAddress(self, version):
    return self.GetRemoteAddress(version)

  def _QuietDeleteLink(self, ifname):
    try:
      self.iproute.DeleteLink(ifname)
    except IOError:
      # link was not present
      pass

  # TODO: take encryption and auth parameters
  def _CreateXfrmTunnel(self, direction, inner_family, src_addr, src_prefixlen,
                        dst_addr, dst_prefixlen, outer_family, tsrc_addr,
                        tdst_addr, spi, mark=None, output_mark=None):
    """Create an XFRM Tunnel Consisting of a Policy and an SA

    Create a unidirectional XFRM tunnel, which entails one Policy and one
    security association.

    Args:
      direction: XFRM_POLICY_IN or XFRM_POLICY_OUT
      inner_family: The address family (AF_INET or AF_INET6) of the tunneled
        packets
      src_addr: The source address of the inner packets to be tunneled
      src_prefixlen: The number of bits in src_addr to match
      dst_addr: The destination address of the inner packets to be tunneled
      dst_prefixlen: The number of bits in dst_addr to match
      outer_family: The address family (AF_INET or AF_INET6) the tunnel
      tsrc_addr: The source address of the tunneled packets
      tdst_addr: The destination address of the tunneled packets
      spi: The SPI for the IPsec SA that encapsulates the tunneled packet
      mark: The mark used for selecting packets to be tunneled, and for
        matching the security policy and security association.
    """
    self.xfrm.AddMinimalSaInfo(
        tsrc_addr, tdst_addr,
        htonl(spi), IPPROTO_ESP, xfrm.XFRM_MODE_TUNNEL, 0,
        xfrm_base._ALGO_CBC_AES_256, xfrm_base._ENCRYPTION_KEY_256,
        xfrm_base._ALGO_HMAC_SHA1, xfrm_base._AUTHENTICATION_KEY_128, None,
        mark, xfrm_base.MARK_MASK_ALL if mark is not None else None,
        output_mark)

    sel = xfrm.XfrmSelector(
        daddr=xfrm.PaddedAddress(dst_addr),
        saddr=xfrm.PaddedAddress(src_addr),
        prefixlen_d=dst_prefixlen,
        prefixlen_s=src_prefixlen,
        family=inner_family)

    policy = xfrm.XfrmUserpolicyInfo(
        sel=sel,
        lft=xfrm.NO_LIFETIME_CFG,
        curlft=xfrm.NO_LIFETIME_CUR,
        priority=100,
        index=0,
        dir=direction,
        action=xfrm.XFRM_POLICY_ALLOW,
        flags=xfrm.XFRM_POLICY_LOCALOK,
        share=xfrm.XFRM_SHARE_ANY)

    # Create a template that specifies the SPI and the protocol.
    xfrmid = xfrm.XfrmId(
        daddr=xfrm.PaddedAddress(tdst_addr), spi=htonl(spi), proto=IPPROTO_ESP)
    tmpl = xfrm.XfrmUserTmpl(
        id=xfrmid,
        family=outer_family,
        saddr=xfrm.PaddedAddress(tsrc_addr),
        reqid=0,
        mode=xfrm.XFRM_MODE_TUNNEL,
        share=xfrm.XFRM_SHARE_ANY,
        optional=0,  # require
        aalgos=xfrm_base.ALL_ALGORITHMS,  # auth algos
        ealgos=xfrm_base.ALL_ALGORITHMS,  # encryption algos
        calgos=xfrm_base.ALL_ALGORITHMS)  # compression algos

    self.xfrm.AddPolicyInfo(policy, tmpl,
                            xfrm.XfrmMark((mark, xfrm_base.MARK_MASK_ALL))
                            if mark else None)

  def _CheckTunnelOutput(self, inner_version, outer_version):
    """Test a bi-directional XFRM Tunnel with explicit selectors"""
    underlying_netid = self.RandomNetid()
    netid = self.RandomNetid(exclude=underlying_netid)
    s = socket(net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
    self.SelectInterface(s, netid, "mark")
    local_inner = self.MyAddress(inner_version, netid)
    remote_inner = self._GetRemoteInnerAddress(inner_version)
    local_outer = self.MyAddress(outer_version, underlying_netid)
    remote_outer = self._GetRemoteOuterAddress(outer_version)
    self._CreateXfrmTunnel(
        direction=xfrm.XFRM_POLICY_OUT,
        inner_family=net_test.GetAddressFamily(inner_version),
        src_addr=local_inner,
        src_prefixlen=net_test.AddressLengthBits(inner_version),
        dst_addr=remote_inner,
        dst_prefixlen=net_test.AddressLengthBits(inner_version),
        outer_family=net_test.GetAddressFamily(outer_version),
        tsrc_addr=local_outer,
        tdst_addr=remote_outer,
        mark=None,
        spi=_TEST_OUT_SPI,
        output_mark=underlying_netid)

    self._CreateXfrmTunnel(
        direction=xfrm.XFRM_POLICY_IN,
        inner_family=net_test.GetAddressFamily(inner_version),
        src_addr=remote_inner,
        src_prefixlen=net_test.AddressLengthBits(inner_version),
        dst_addr=local_inner,
        dst_prefixlen=0,
        outer_family=net_test.GetAddressFamily(outer_version),
        tsrc_addr=remote_outer,
        tdst_addr=local_outer,
        mark=None,
        spi=_TEST_IN_SPI)

    s.sendto(net_test.UDP_PAYLOAD, (remote_inner, 53))
    self._ExpectEspPacketOn(underlying_netid, _TEST_OUT_SPI, 1,
                            None, local_outer, remote_outer)

  @unittest.skipUnless(net_test.LINUX_VERSION >= (4, 9, 0), "not yet backported")
  def testIpv4InIpv4TunnelOutput(self):
    self._CheckTunnelOutput(4, 4)

  @unittest.skipUnless(net_test.LINUX_VERSION >= (4, 9, 0), "not yet backported")
  def testIpv4InIpv6TunnelOutput(self):
    self._CheckTunnelOutput(4, 6)

  @unittest.skipUnless(net_test.LINUX_VERSION >= (4, 9, 0), "not yet backported")
  def testIpv6InIpv4TunnelOutput(self):
    self._CheckTunnelOutput(6, 4)

  @unittest.skipUnless(net_test.LINUX_VERSION >= (4, 9, 0), "not yet backported")
  def testIpv6InIpv6TunnelOutput(self):
    self._CheckTunnelOutput(6, 6)

  @unittest.skipUnless(net_test.LINUX_VERSION >= (3, 18, 0), "vti unsupported")
  def testAddVti(self):
    """Test the creation of a Virtual Tunnel Interface"""
    for version in [4, 6]:
      netid = self.RandomNetid()
      local_addr = self.MyAddress(version, netid)
      self.iproute.CreateVirtualTunnelInterface(
          dev_name=_VTI_IFNAME,
          local_addr=local_addr,
          remote_addr=self._GetRemoteOuterAddress(version),
          o_key=_TEST_OKEY,
          i_key=_TEST_IKEY)
      if_index = self.iproute.GetIfIndex(_VTI_IFNAME)

      # Validate that the netlink interface matches the ioctl interface
      self.assertEquals(net_test.GetInterfaceIndex(_VTI_IFNAME), if_index)
      self.iproute.DeleteLink(_VTI_IFNAME)
      with self.assertRaises(IOError):
        self.iproute.GetIfIndex(_VTI_IFNAME)

  def _SetupVtiNetwork(self, ifname, is_add):
    """Setup rules and routes for a VTI Network

    Takes an interface and depending on the boolean
    value of is_add, either adds or removes the rules
    and routes for a VTI to behave like an Android
    Network for purposes of testing.

    Args:
      ifname: The name of a linux interface
      is_add: boolean that set up if is_add is True or
        teardown if is_add is False
    """
    if is_add:
      net_test.SetInterfaceUp(_VTI_IFNAME)
    for version in [4, 6]:
      # Find out how to configure things.
      ifindex = net_test.GetInterfaceIndex(ifname)
      table = _VTI_NETID

      # Set up routing rules.
      start, end = self.UidRangeForNetid(_VTI_NETID)
      self.iproute.UidRangeRule(version, is_add, start, end, table,
                                self.PRIORITY_UID)
      self.iproute.OifRule(version, is_add, ifname, table, self.PRIORITY_OIF)
      self.iproute.FwmarkRule(version, is_add, _VTI_NETID, table,
                              self.PRIORITY_FWMARK)
      if is_add:
        # Add the actual inner address of the tunnel to the VTI Interface
        self.iproute.AddAddress(
            self._GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
        self.iproute.AddRoute(version, table, "default", 0, None, ifindex)
      else:
        self.iproute.DelRoute(version, table, "default", 0, None, ifindex)
        # the actual inner address of the tunnel to the VTI Interface
        self.iproute.DelAddress(
            self._GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
    if not is_add:
      net_test.SetInterfaceDown(_VTI_IFNAME)

  def _CheckVtiOutput(self, inner_version, outer_version):
    """Test packet output over an IPsec tunnel that is selected using a VTI"""
    netid = self.RandomNetid()
    local_outer = self.MyAddress(outer_version, netid)
    remote_outer = self._GetRemoteOuterAddress(outer_version)
    self.iproute.CreateVirtualTunnelInterface(
        dev_name=_VTI_IFNAME,
        local_addr=local_outer,
        remote_addr=remote_outer,
        i_key=_TEST_IKEY,
        o_key=_TEST_OKEY)
    self._SetupVtiNetwork(_VTI_IFNAME, True)

    try:
      inner_addr = net_test.GetWildcardAddress(inner_version)
      self._CreateXfrmTunnel(
          direction=xfrm.XFRM_POLICY_OUT,
          inner_family=net_test.GetAddressFamily(inner_version),
          src_addr=inner_addr,
          src_prefixlen=0,
          dst_addr=inner_addr,
          dst_prefixlen=0,
          outer_family=net_test.GetAddressFamily(outer_version),
          tsrc_addr=local_outer,
          tdst_addr=remote_outer,
          mark=_TEST_OKEY,
          spi=_TEST_OUT_SPI,
          output_mark=netid)

      self._CreateXfrmTunnel(
          direction=xfrm.XFRM_POLICY_IN,
          inner_family=net_test.GetAddressFamily(inner_version),
          src_addr=inner_addr,
          src_prefixlen=0,
          dst_addr=inner_addr,
          dst_prefixlen=0,
          outer_family=net_test.GetAddressFamily(outer_version),
          tsrc_addr=remote_outer,
          tdst_addr=local_outer,
          mark=_TEST_IKEY,
          spi=_TEST_IN_SPI,
          output_mark=netid)

      s = socket(net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
      self.SelectInterface(s, _VTI_NETID, "mark")

      s.sendto(net_test.UDP_PAYLOAD,
               (self._GetRemoteInnerAddress(inner_version), 53))
      self._ExpectEspPacketOn(netid, _TEST_OUT_SPI, 1, None, local_outer,
                              remote_outer)

    finally:
      self._SetupVtiNetwork(_VTI_IFNAME, False)

  @unittest.skipUnless(net_test.LINUX_VERSION >= (4, 9, 0), "not yet backported")
  def testIpv4InIpv4VtiOutput(self):
    self._CheckVtiOutput(4, 4)

  @unittest.skipUnless(net_test.LINUX_VERSION >= (4, 9, 0), "not yet backported")
  def testIpv4InIpv6VtiOutput(self):
    self._CheckVtiOutput(4, 6)

  @unittest.skipUnless(net_test.LINUX_VERSION >= (4, 9, 0), "not yet backported")
  def testIpv6InIpv4VtiOutput(self):
    self._CheckVtiOutput(6, 4)

  @unittest.skipUnless(net_test.LINUX_VERSION >= (4, 9, 0), "not yet backported")
  def testIpv6InIpv6VtiOutput(self):
    self._CheckVtiOutput(6, 6)


if __name__ == "__main__":
  unittest.main()
