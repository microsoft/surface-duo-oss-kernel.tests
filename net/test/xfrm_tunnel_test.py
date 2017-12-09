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

from tun_twister import TunTwister
import csocket
import iproute
import multinetwork_base
import net_test
import xfrm
import xfrm_base

# Parameters to Set up VTI as a special network
_VTI_NETID = 50
_VTI_IFNAME = "test_vti"

_TEST_OUT_SPI = 0x1234
_TEST_IN_SPI = _TEST_OUT_SPI

_TEST_OKEY = _TEST_OUT_SPI + _VTI_NETID
_TEST_IKEY = _TEST_IN_SPI + _VTI_NETID


@unittest.skipUnless(net_test.LINUX_VERSION >= (3, 18, 0), "VTI Unsupported")
class XfrmTunnelTest(xfrm_base.XfrmBaseTest):

  def setUp(self):
    super(XfrmTunnelTest, self).setUp()
    # If the hard-coded netids are redefined this will catch the error.
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
      # The link was not present.
      pass

  def _SwapInterfaceAddress(self, ifname, old_addr, new_addr):
    """Exchange two addresses on a given interface.

    Args:
      ifname: Name of the interface
      old_addr: An address to be removed from the interface
      new_addr: An address to be added to an interface
    """
    version = 6 if ":" in new_addr else 4
    ifindex = net_test.GetInterfaceIndex(ifname)
    self.iproute.AddAddress(new_addr,
                            net_test.AddressLengthBits(version), ifindex)
    self.iproute.DelAddress(old_addr,
                            net_test.AddressLengthBits(version), ifindex)

  # TODO: Take encryption and auth parameters.
  def _CreateXfrmTunnel(self,
                        direction,
                        selector,
                        outer_family,
                        tsrc_addr,
                        tdst_addr,
                        spi,
                        mark=None,
                        output_mark=None):
    """Create an XFRM Tunnel Consisting of a Policy and an SA.

    Create a unidirectional XFRM tunnel, which entails one Policy and one
    security association.

    Args:
      direction: XFRM_POLICY_IN or XFRM_POLICY_OUT
      selector: An XfrmSelector that specifies the packets to be transformed.
      outer_family: The address family (AF_INET or AF_INET6) the tunnel
      tsrc_addr: The source address of the tunneled packets
      tdst_addr: The destination address of the tunneled packets
      spi: The SPI for the IPsec SA that encapsulates the tunneled packet
      mark: The mark used for selecting packets to be tunneled, and for
        matching the security policy and security association.
      output_mark: The mark used to select the underlying network for packets
        outbound from xfrm.
    """
    self.xfrm.AddSaInfo(
        tsrc_addr, tdst_addr,
        htonl(spi), xfrm.XFRM_MODE_TUNNEL, 0, selector,
        xfrm_base._ALGO_CBC_AES_256,
        xfrm_base._ALGO_HMAC_SHA1,
        None,
        mark,
        output_mark)

    policy = xfrm_base.UserPolicy(direction, selector)
    tmpl = xfrm_base.UserTemplate(outer_family, htonl(spi), 0,
                                    (tsrc_addr, tdst_addr))
    self.xfrm.AddPolicyInfo(policy, tmpl, mark)

  def _CheckTunnelOutput(self, inner_version, outer_version):
    """Test a bi-directional XFRM Tunnel with explicit selectors"""
    # Select the underlying netid, which represents the external
    # interface from/to which to route ESP packets.
    underlying_netid = self.RandomNetid()
    # Select a random netid that will originate traffic locally and
    # which represents the logical tunnel network.
    netid = self.RandomNetid(exclude=underlying_netid)

    local_inner = self.MyAddress(inner_version, netid)
    remote_inner = self._GetRemoteInnerAddress(inner_version)
    local_outer = self.MyAddress(outer_version, underlying_netid)
    remote_outer = self._GetRemoteOuterAddress(outer_version)

    self._CreateXfrmTunnel(
        direction=xfrm.XFRM_POLICY_OUT,
        selector=xfrm.SrcDstSelector(local_inner, remote_inner),
        outer_family=net_test.GetAddressFamily(outer_version),
        tsrc_addr=local_outer,
        tdst_addr=remote_outer,
        spi=_TEST_OUT_SPI,
        output_mark=underlying_netid)

    write_sock = socket(net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
    # Select an interface, which provides the source address of the inner
    # packet.
    self.SelectInterface(write_sock, netid, "mark")
    write_sock.sendto(net_test.UDP_PAYLOAD, (remote_inner, 53))
    self._ExpectEspPacketOn(underlying_netid, _TEST_OUT_SPI, 1, None,
                            local_outer, remote_outer)

  # TODO: Add support for the input path.

  def testIpv4InIpv4TunnelOutput(self):
    self._CheckTunnelOutput(4, 4)

  def testIpv4InIpv6TunnelOutput(self):
    self._CheckTunnelOutput(4, 6)

  def testIpv6InIpv4TunnelOutput(self):
    self._CheckTunnelOutput(6, 4)

  def testIpv6InIpv6TunnelOutput(self):
    self._CheckTunnelOutput(6, 6)

  def testAddVti(self):
    """Test the creation of a Virtual Tunnel Interface."""
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

      # Validate that the netlink interface matches the ioctl interface.
      self.assertEquals(net_test.GetInterfaceIndex(_VTI_IFNAME), if_index)
      self.iproute.DeleteLink(_VTI_IFNAME)
      with self.assertRaises(IOError):
        self.iproute.GetIfIndex(_VTI_IFNAME)

  def _SetupVtiNetwork(self, ifname, is_add):
    """Setup rules and routes for a VTI Network.

    Takes an interface and depending on the boolean
    value of is_add, either adds or removes the rules
    and routes for a VTI to behave like an Android
    Network for purposes of testing.

    Args:
      ifname: The name of a linux interface
      is_add: Boolean that causes this method to perform setup if True or
        teardown if False
    """
    if is_add:
      # Bring up the interface so that we can start adding addresses
      # and routes.
      net_test.SetInterfaceUp(_VTI_IFNAME)

      # Disable router solicitations to avoid occasional spurious packets
      # arriving on the underlying network; there are two possible behaviors
      # when that occurred: either only the RA packet is read, and when it
      # is echoed back to the VTI, it causes the test to fail by not receiving
      # the UDP_PAYLOAD; or, two packets may arrive on the underlying
      # network which fails the assertion that only one ESP packet is received.
      self.SetSysctl(
          "/proc/sys/net/ipv6/conf/%s/router_solicitations" % _VTI_IFNAME, 0)
    for version in [4, 6]:
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
        self.iproute.AddAddress(
            self._GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
        self.iproute.AddRoute(version, table, "default", 0, None, ifindex)
      else:
        self.iproute.DelRoute(version, table, "default", 0, None, ifindex)
        self.iproute.DelAddress(
            self._GetLocalInnerAddress(version),
            net_test.AddressLengthBits(version), ifindex)
    if not is_add:
      net_test.SetInterfaceDown(_VTI_IFNAME)

  # TODO: Should we completely re-write this using null encryption and null
  # authentication? We could then assemble and disassemble packets for each
  # direction individually. This approach would improve debuggability, avoid the
  # complexity of the twister, and allow the test to more-closely validate
  # deployable configurations.
  def _CheckVtiOutput(self, inner_version, outer_version):
    """Test packet input and output over a Virtual Tunnel Interface."""
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
      # For the VTI, the selectors are wildcard since packets will only
      # be selected if they have the appropriate mark, hence the inner
      # addresses are wildcard.
      self._CreateXfrmTunnel(
          direction=xfrm.XFRM_POLICY_OUT,
          selector=xfrm.EmptySelector(net_test.GetAddressFamily(inner_version)),
          outer_family=net_test.GetAddressFamily(outer_version),
          tsrc_addr=local_outer,
          tdst_addr=remote_outer,
          mark=xfrm.ExactMatchMark(_TEST_OKEY),
          spi=_TEST_OUT_SPI,
          output_mark=netid)

      self._CreateXfrmTunnel(
          direction=xfrm.XFRM_POLICY_IN,
          selector=xfrm.EmptySelector(net_test.GetAddressFamily(inner_version)),
          outer_family=net_test.GetAddressFamily(outer_version),
          tsrc_addr=remote_outer,
          tdst_addr=local_outer,
          mark=xfrm.ExactMatchMark(_TEST_IKEY),
          spi=_TEST_IN_SPI,
          output_mark=netid)

      # Create a socket to receive packets.
      read_sock = socket(
          net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
      read_sock.bind((net_test.GetWildcardAddress(inner_version), 0))
      # The second parameter of the tuple is the port number regardless of AF.
      port = read_sock.getsockname()[1]
      # Guard against the eventuality of the receive failing.
      csocket.SetSocketTimeout(read_sock, 100)

      # Send a packet out via the vti-backed network, bound for the port number
      # of the input socket.
      write_sock = socket(
          net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
      self.SelectInterface(write_sock, _VTI_NETID, "mark")
      write_sock.sendto(net_test.UDP_PAYLOAD,
                        (self._GetRemoteInnerAddress(inner_version), port))

      # Read a tunneled IP packet on the underlying (outbound) network
      # verifying that it is an ESP packet.
      pkt = self._ExpectEspPacketOn(netid, _TEST_OUT_SPI, 1, None, local_outer,
                                    remote_outer)

      # Perform an address switcheroo so that the inner address of the remote
      # end of the tunnel is now the address on the local VTI interface; this
      # way, the twisted inner packet finds a destination via the VTI once
      # decrypted.
      remote = self._GetRemoteInnerAddress(inner_version)
      local = self._GetLocalInnerAddress(inner_version)
      self._SwapInterfaceAddress(_VTI_IFNAME, new_addr=remote, old_addr=local)
      try:
        # Swap the packet's IP headers and write it back to the
        # underlying network.
        pkt = TunTwister.TwistPacket(pkt)
        self.ReceivePacketOn(netid, pkt)
        # Receive the decrypted packet on the dest port number.
        read_packet = read_sock.recv(4096)
        self.assertEquals(read_packet, net_test.UDP_PAYLOAD)
      finally:
        # Unwind the switcheroo
        self._SwapInterfaceAddress(_VTI_IFNAME, new_addr=local, old_addr=remote)

    finally:
      self._SetupVtiNetwork(_VTI_IFNAME, False)

  def testIpv4InIpv4VtiOutput(self):
    self._CheckVtiOutput(4, 4)

  def testIpv4InIpv6VtiOutput(self):
    self._CheckVtiOutput(4, 6)

  def testIpv6InIpv4VtiOutput(self):
    self._CheckVtiOutput(6, 4)

  def testIpv6InIpv6VtiOutput(self):
    self._CheckVtiOutput(6, 6)


if __name__ == "__main__":
  unittest.main()
