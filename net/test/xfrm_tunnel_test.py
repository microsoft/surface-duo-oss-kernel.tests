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

import random
import itertools
import struct
import unittest

from scapy import all as scapy
from tun_twister import TunTwister
import csocket
import iproute
import multinetwork_base
import net_test
import packets
import util
import xfrm
import xfrm_base

_LOOPBACK_IFINDEX = 1
_TEST_XFRM_IFNAME = "ipsec42"
_TEST_XFRM_IF_ID = 42

# Does the kernel support xfrmi interfaces?
def HaveXfrmInterfaces():
  try:
    i = iproute.IPRoute()
    i.CreateXfrmInterface(_TEST_XFRM_IFNAME, _TEST_XFRM_IF_ID,
                          _LOOPBACK_IFINDEX)
    i.DeleteLink(_TEST_XFRM_IFNAME)
    try:
      i.GetIfIndex(_TEST_XFRM_IFNAME)
      assert "Deleted interface %s still exists!" % _TEST_XFRM_IFNAME
    except IOError:
      pass
    return True
  except IOError:
    return False

HAVE_XFRM_INTERFACES = HaveXfrmInterfaces()

# Parameters to Set up VTI as a special network
_BASE_VTI_NETID = {4: 40, 6: 60}
_BASE_VTI_OKEY = 2000000100
_BASE_VTI_IKEY = 2000000200

_VTI_NETID = 50
_VTI_IFNAME = "test_vti"

_TEST_OUT_SPI = 0x1234
_TEST_IN_SPI = _TEST_OUT_SPI

_TEST_OKEY = 2000000100
_TEST_IKEY = 2000000200


def _GetLocalInnerAddress(version):
  return {4: "10.16.5.15", 6: "2001:db8:1::1"}[version]


def _GetRemoteInnerAddress(version):
  return {4: "10.16.5.20", 6: "2001:db8:2::1"}[version]


def _GetRemoteOuterAddress(version):
  return {4: net_test.IPV4_ADDR, 6: net_test.IPV6_ADDR}[version]


def InjectTests():
  InjectParameterizedTests(XfrmTunnelTest)


def InjectParameterizedTests(cls):
  VERSIONS = (4, 6)
  param_list = itertools.product(VERSIONS, VERSIONS)

  def NameGenerator(*args):
    return "IPv%d_in_IPv%d" % tuple(args)

  util.InjectParameterizedTest(cls, param_list, NameGenerator)


class XfrmTunnelTest(xfrm_base.XfrmLazyTest):

  def _CheckTunnelOutput(self, inner_version, outer_version, underlying_netid,
                         netid, local_inner, remote_inner, local_outer,
                         remote_outer, write_sock):

    write_sock.sendto(net_test.UDP_PAYLOAD, (remote_inner, 53))
    self._ExpectEspPacketOn(underlying_netid, _TEST_OUT_SPI, 1, None,
                            local_outer, remote_outer)

  def _CheckTunnelInput(self, inner_version, outer_version, underlying_netid,
                        netid, local_inner, remote_inner, local_outer,
                        remote_outer, read_sock):

    # The second parameter of the tuple is the port number regardless of AF.
    local_port = read_sock.getsockname()[1]

    # Build and receive an ESP packet destined for the inner socket
    IpType = {4: scapy.IP, 6: scapy.IPv6}[inner_version]
    input_pkt = (
        IpType(src=remote_inner, dst=local_inner) / scapy.UDP(
            sport=1234, dport=local_port) / net_test.UDP_PAYLOAD)
    input_pkt = IpType(str(input_pkt))  # Compute length, checksum.
    input_pkt = xfrm_base.EncryptPacketWithNull(input_pkt, _TEST_IN_SPI, 1,
                                                (remote_outer, local_outer))
    self.ReceivePacketOn(underlying_netid, input_pkt)

    # Verify that the packet data and src are correct
    data, src = read_sock.recvfrom(4096)
    self.assertEquals(net_test.UDP_PAYLOAD, data)
    self.assertEquals(remote_inner, src[0])
    self.assertEquals(1234, src[1])

  def _TestTunnel(self, inner_version, outer_version, func, direction):
    """Test a unidirectional XFRM Tunnel with explicit selectors"""
    # Select the underlying netid, which represents the external
    # interface from/to which to route ESP packets.
    u_netid = self.RandomNetid()
    # Select a random netid that will originate traffic locally and
    # which represents the netid on which the plaintext is sent
    netid = self.RandomNetid(exclude=u_netid)

    local_inner = self.MyAddress(inner_version, netid)
    remote_inner = _GetRemoteInnerAddress(inner_version)
    local_outer = self.MyAddress(outer_version, u_netid)
    remote_outer = _GetRemoteOuterAddress(outer_version)

    # Create input/ouput SPs, SAs and sockets to simulate a more realistic
    # environment.
    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_IN,
                           xfrm.SrcDstSelector(remote_inner, local_inner),
                           remote_outer, local_outer, _TEST_IN_SPI,
                           xfrm_base._ALGO_CRYPT_NULL,
                           xfrm_base._ALGO_AUTH_NULL, None, None, None)

    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_OUT,
                           xfrm.SrcDstSelector(local_inner, remote_inner),
                           local_outer, remote_outer, _TEST_OUT_SPI,
                           xfrm_base._ALGO_CBC_AES_256,
                           xfrm_base._ALGO_HMAC_SHA1, None, u_netid, None)

    write_sock = socket(net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
    self.SelectInterface(write_sock, netid, "mark")
    read_sock = socket(net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
    read_sock.bind((net_test.GetWildcardAddress(inner_version), 0))
    # Guard against the eventuality of the receive failing.
    net_test.SetNonBlocking(read_sock.fileno())

    sock = write_sock if direction == xfrm.XFRM_POLICY_OUT else read_sock
    func(inner_version, outer_version, u_netid, netid, local_inner,
         remote_inner, local_outer, remote_outer, sock)

  def ParamTestTunnelInput(self, inner_version, outer_version):
    self._TestTunnel(inner_version, outer_version, self._CheckTunnelInput,
                     xfrm.XFRM_POLICY_IN)

  def ParamTestTunnelOutput(self, inner_version, outer_version):
    self._TestTunnel(inner_version, outer_version, self._CheckTunnelOutput,
                     xfrm.XFRM_POLICY_OUT)


@unittest.skipUnless(net_test.LINUX_VERSION >= (3, 18, 0), "VTI Unsupported")
class XfrmAddDeleteVtiTest(xfrm_base.XfrmBaseTest):
  def _VerifyVtiInfoData(self, vti_info_data, version, local_addr, remote_addr,
                         ikey, okey):
    self.assertEquals(vti_info_data["IFLA_VTI_IKEY"], ikey)
    self.assertEquals(vti_info_data["IFLA_VTI_OKEY"], okey)

    family = AF_INET if version == 4 else AF_INET6
    self.assertEquals(inet_ntop(family, vti_info_data["IFLA_VTI_LOCAL"]),
                      local_addr)
    self.assertEquals(inet_ntop(family, vti_info_data["IFLA_VTI_REMOTE"]),
                      remote_addr)

  def testAddVti(self):
    """Test the creation of a Virtual Tunnel Interface."""
    for version in [4, 6]:
      netid = self.RandomNetid()
      local_addr = self.MyAddress(version, netid)
      self.iproute.CreateVirtualTunnelInterface(
          dev_name=_VTI_IFNAME,
          local_addr=local_addr,
          remote_addr=_GetRemoteOuterAddress(version),
          o_key=_TEST_OKEY,
          i_key=_TEST_IKEY)
      self._VerifyVtiInfoData(self.iproute.GetIfinfoData(_VTI_IFNAME),
                             version, local_addr,
                             _GetRemoteOuterAddress(version),
                             _TEST_IKEY, _TEST_OKEY)

      new_remote_addr = {4: net_test.IPV4_ADDR2, 6: net_test.IPV6_ADDR2}
      new_okey = _TEST_OKEY + _VTI_NETID
      new_ikey = _TEST_IKEY + _VTI_NETID
      self.iproute.CreateVirtualTunnelInterface(
          dev_name=_VTI_IFNAME,
          local_addr=local_addr,
          remote_addr=new_remote_addr[version],
          o_key=new_okey,
          i_key=new_ikey,
          is_update=True)

      self._VerifyVtiInfoData(self.iproute.GetIfinfoData(_VTI_IFNAME),
                             version, local_addr, new_remote_addr[version],
                             new_ikey, new_okey)

      if_index = self.iproute.GetIfIndex(_VTI_IFNAME)

      # Validate that the netlink interface matches the ioctl interface.
      self.assertEquals(net_test.GetInterfaceIndex(_VTI_IFNAME), if_index)
      self.iproute.DeleteLink(_VTI_IFNAME)
      with self.assertRaises(IOError):
        self.iproute.GetIfIndex(_VTI_IFNAME)

  def _QuietDeleteLink(self, ifname):
    try:
      self.iproute.DeleteLink(ifname)
    except IOError:
      # The link was not present.
      pass

  def tearDown(self):
    super(XfrmAddDeleteVtiTest, self).tearDown()
    self._QuietDeleteLink(_VTI_IFNAME)


class VtiInterface(object):

  def __init__(self, iface, netid, underlying_netid, _, local, remote):
    self.iface = iface
    self.netid = netid
    self.underlying_netid = underlying_netid
    self.local, self.remote = local, remote
    self.rx = self.tx = 0
    self.ikey = _TEST_IKEY + netid
    self.okey = _TEST_OKEY + netid
    self.out_spi = self.in_spi = random.randint(0, 0x7fffffff)

    self.iproute = iproute.IPRoute()
    self.xfrm = xfrm.Xfrm()

    self.SetupInterface()
    self.SetupXfrm()
    self.addrs = {}

  def Teardown(self):
    self.TeardownXfrm()
    self.TeardownInterface()

  def SetupInterface(self):
    return self.iproute.CreateVirtualTunnelInterface(
        self.iface, self.local, self.remote, self.ikey, self.okey)

  def TeardownInterface(self):
    self.iproute.DeleteLink(self.iface)

  def SetupXfrm(self):
    # For the VTI, the selectors are wildcard since packets will only
    # be selected if they have the appropriate mark, hence the inner
    # addresses are wildcard.
    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_OUT, None, self.local, self.remote,
                           self.out_spi, xfrm_base._ALGO_CBC_AES_256,
                           xfrm_base._ALGO_HMAC_SHA1,
                           xfrm.ExactMatchMark(self.okey),
                           self.underlying_netid, None)

    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_IN, None, self.remote, self.local,
                           self.in_spi, xfrm_base._ALGO_CBC_AES_256,
                           xfrm_base._ALGO_HMAC_SHA1,
                           xfrm.ExactMatchMark(self.ikey), None, None)

  def TeardownXfrm(self):
    self.xfrm.DeleteTunnel(xfrm.XFRM_POLICY_OUT, None, self.remote,
                           self.out_spi, self.okey, None)
    self.xfrm.DeleteTunnel(xfrm.XFRM_POLICY_IN, None, self.local,
                           self.in_spi, self.ikey, None)


@unittest.skipUnless(HAVE_XFRM_INTERFACES, "XFRM interfaces unsupported")
class XfrmAddDeleteXfrmInterfaceTest(xfrm_base.XfrmBaseTest):
  """Test the creation of an XFRM Interface."""

  def testAddXfrmInterface(self):
    self.iproute.CreateXfrmInterface(_TEST_XFRM_IFNAME, _TEST_XFRM_IF_ID,
                                     _LOOPBACK_IFINDEX)
    if_index = self.iproute.GetIfIndex(_TEST_XFRM_IFNAME)
    net_test.SetInterfaceUp(_TEST_XFRM_IFNAME)

    # Validate that the netlink interface matches the ioctl interface.
    self.assertEquals(net_test.GetInterfaceIndex(_TEST_XFRM_IFNAME), if_index)
    self.iproute.DeleteLink(_TEST_XFRM_IFNAME)
    with self.assertRaises(IOError):
      self.iproute.GetIfIndex(_TEST_XFRM_IFNAME)


class XfrmInterface(object):

  def __init__(self, iface, netid, underlying_netid, ifindex, local, remote):
    self.iface = iface
    self.netid = netid
    self.underlying_netid = underlying_netid
    self.ifindex = ifindex
    self.local, self.remote = local, remote
    self.rx = self.tx = 0
    self.xfrm_if_id = netid
    self.out_spi = self.in_spi = random.randint(0, 0x7fffffff)
    self.xfrm_if_id = self.netid

    self.iproute = iproute.IPRoute()
    self.xfrm = xfrm.Xfrm()

    self.SetupInterface()
    self.SetupXfrm()
    self.addrs = {}

  def Teardown(self):
    self.TeardownXfrm()
    self.TeardownInterface()

  def SetupInterface(self):
    """Create an XFRM interface."""
    return self.iproute.CreateXfrmInterface(self.iface, self.netid, self.ifindex)

  def TeardownInterface(self):
    self.iproute.DeleteLink(self.iface)

  def SetupXfrm(self):
    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_OUT, None, self.local, self.remote,
                           self.out_spi, xfrm_base._ALGO_CBC_AES_256,
                           xfrm_base._ALGO_HMAC_SHA1, None,
                           self.underlying_netid, self.xfrm_if_id)
    self.xfrm.CreateTunnel(xfrm.XFRM_POLICY_IN, None, self.remote, self.local,
                           self.in_spi, xfrm_base._ALGO_CBC_AES_256,
                           xfrm_base._ALGO_HMAC_SHA1,
                           None, None, self.xfrm_if_id)


  def TeardownXfrm(self):
    self.xfrm.DeleteTunnel(xfrm.XFRM_POLICY_OUT, None, self.remote,
                           self.out_spi, None, self.xfrm_if_id)
    self.xfrm.DeleteTunnel(xfrm.XFRM_POLICY_IN, None, self.local,
                           self.in_spi, None, self.xfrm_if_id)



class XfrmTunnelBase(xfrm_base.XfrmBaseTest):

  @classmethod
  def setUpClass(cls):
    xfrm_base.XfrmBaseTest.setUpClass()
    # VTI interfaces use marks extensively, so configure realistic packet
    # marking rules to make the test representative, make PMTUD work, etc.
    cls.SetInboundMarks(True)
    cls.SetMarkReflectSysctls(1)

    cls.tunnels = {}
    for i, underlying_netid in enumerate(cls.tuns):
      for version in 4, 6:
        netid = _BASE_VTI_NETID[version] + i
        iface = "ipsec%s" % netid
        local = cls.MyAddress(version, underlying_netid)
        if version == 4:
          remote = net_test.IPV4_ADDR2 if (i % 2) else net_test.IPV4_ADDR
        else:
          remote = net_test.IPV6_ADDR2 if (i % 2) else net_test.IPV6_ADDR
        ifindex = cls.ifindices[underlying_netid]

        tunnel = cls.INTERFACE_CLASS(iface, netid, underlying_netid, ifindex,
                                     local, remote)

        cls._SetInboundMarking(netid, iface, True)
        cls._SetupTunnelNetwork(tunnel, True)
        cls.tunnels[netid] = tunnel

  @classmethod
  def tearDownClass(cls):
    # The sysctls are restored by MultinetworkBaseTest.tearDownClass.
    cls.SetInboundMarks(False)
    for tunnel in cls.tunnels.values():
      cls._SetInboundMarking(tunnel.netid, tunnel.iface, False)
      cls._SetupTunnelNetwork(tunnel, False)
      tunnel.Teardown()
    xfrm_base.XfrmBaseTest.tearDownClass()

  def setUp(self):
    multinetwork_base.MultiNetworkBaseTest.setUp(self)
    self.iproute = iproute.IPRoute()

  def tearDown(self):
    multinetwork_base.MultiNetworkBaseTest.tearDown(self)

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

  @classmethod
  def _SetupTunnelNetwork(cls, tunnel, is_add):
    """Setup rules and routes for a tunnel Network.

    Takes an interface and depending on the boolean
    value of is_add, either adds or removes the rules
    and routes for a tunnel interface to behave like an
    Android Network for purposes of testing.

    Args:
      tunnel: A VtiInterface or XfrmInterface, the tunnel to set up.
      is_add: Boolean that causes this method to perform setup if True or
        teardown if False
    """
    if is_add:
      # Disable router solicitations to avoid occasional spurious packets
      # arriving on the underlying network; there are two possible behaviors
      # when that occurred: either only the RA packet is read, and when it
      # is echoed back to the tunnel, it causes the test to fail by not
      # receiving # the UDP_PAYLOAD; or, two packets may arrive on the
      # underlying # network which fails the assertion that only one ESP packet
      # is received.
      cls.SetSysctl(
          "/proc/sys/net/ipv6/conf/%s/router_solicitations" % tunnel.iface, 0)
      net_test.SetInterfaceUp(tunnel.iface)

    for version in [4, 6]:
      ifindex = net_test.GetInterfaceIndex(tunnel.iface)
      table = tunnel.netid

      # Set up routing rules.
      start, end = cls.UidRangeForNetid(tunnel.netid)
      cls.iproute.UidRangeRule(version, is_add, start, end, table,
                                cls.PRIORITY_UID)
      cls.iproute.OifRule(version, is_add, tunnel.iface, table, cls.PRIORITY_OIF)
      cls.iproute.FwmarkRule(version, is_add, tunnel.netid, cls.NETID_FWMASK,
                              table, cls.PRIORITY_FWMARK)

      # Configure IP addresses.
      if version == 4:
        addr = cls._MyIPv4Address(tunnel.netid)
      else:
        addr = cls.OnlinkPrefix(6, tunnel.netid) + "1"
      prefixlen = net_test.AddressLengthBits(version)
      tunnel.addrs[version] = addr
      if is_add:
        cls.iproute.AddAddress(addr, prefixlen, ifindex)
        cls.iproute.AddRoute(version, table, "default", 0, None, ifindex)
      else:
        cls.iproute.DelRoute(version, table, "default", 0, None, ifindex)
        cls.iproute.DelAddress(addr, prefixlen, ifindex)

  def assertReceivedPacket(self, tunnel):
    tunnel.rx += 1
    self.assertEquals((tunnel.rx, tunnel.tx),
                      self.iproute.GetRxTxPackets(tunnel.iface))

  def assertSentPacket(self, tunnel):
    tunnel.tx += 1
    self.assertEquals((tunnel.rx, tunnel.tx),
                      self.iproute.GetRxTxPackets(tunnel.iface))

  # TODO: Should we completely re-write this using null encryption and null
  # authentication? We could then assemble and disassemble packets for each
  # direction individually. This approach would improve debuggability, avoid the
  # complexity of the twister, and allow the test to more-closely validate
  # deployable configurations.
  def _CheckTunnelInputOutput(self, tunnel, inner_version):
    local_outer = tunnel.local
    remote_outer = tunnel.remote

    # Create a socket to receive packets.
    read_sock = socket(
        net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
    read_sock.bind((net_test.GetWildcardAddress(inner_version), 0))
    # The second parameter of the tuple is the port number regardless of AF.
    port = read_sock.getsockname()[1]
    # Guard against the eventuality of the receive failing.
    net_test.SetNonBlocking(read_sock.fileno())

    # Send a packet out via the tunnel-backed network, bound for the port number
    # of the input socket.
    write_sock = socket(
        net_test.GetAddressFamily(inner_version), SOCK_DGRAM, 0)
    self.SelectInterface(write_sock, tunnel.netid, "mark")
    write_sock.sendto(net_test.UDP_PAYLOAD,
                      (_GetRemoteInnerAddress(inner_version), port))

    # Read a tunneled IP packet on the underlying (outbound) network
    # verifying that it is an ESP packet.
    self.assertSentPacket(tunnel)
    pkt = self._ExpectEspPacketOn(tunnel.underlying_netid, tunnel.out_spi, tunnel.tx, None,
                                  local_outer, remote_outer)

    # Perform an address switcheroo so that the inner address of the remote
    # end of the tunnel is now the address on the local tunnel interface; this
    # way, the twisted inner packet finds a destination via the tunnel once
    # decrypted.
    remote = _GetRemoteInnerAddress(inner_version)
    local = tunnel.addrs[inner_version]
    self._SwapInterfaceAddress(tunnel.iface, new_addr=remote, old_addr=local)
    try:
      # Swap the packet's IP headers and write it back to the
      # underlying network.
      pkt = TunTwister.TwistPacket(pkt)
      self.ReceivePacketOn(tunnel.underlying_netid, pkt)
      self.assertReceivedPacket(tunnel)
      # Receive the decrypted packet on the dest port number.
      read_packet = read_sock.recv(4096)
      self.assertEquals(read_packet, net_test.UDP_PAYLOAD)
      self.assertReceivedPacket(vti)
    finally:
      # Unwind the switcheroo
      self._SwapInterfaceAddress(tunnel.iface, new_addr=local, old_addr=remote)

    # Now attempt to provoke an ICMP error.
    # TODO: deduplicate with multinetwork_test.py.
    version = net_test.GetAddressVersion(tunnel.remote)
    dst_prefix, intermediate = {
        4: ("172.19.", "172.16.9.12"),
        6: ("2001:db8::", "2001:db8::1")
    }[version]

    write_sock.sendto(net_test.UDP_PAYLOAD,
                      (_GetRemoteInnerAddress(inner_version), port))
    self.assertSentPacket(tunnel)
    pkt = self._ExpectEspPacketOn(tunnel.underlying_netid, tunnel.out_spi, tunnel.tx, None,
                                  local_outer, remote_outer)
    myaddr = self.MyAddress(version, tunnel.underlying_netid)
    _, toobig = packets.ICMPPacketTooBig(version, intermediate, myaddr, pkt)
    self.ReceivePacketOn(tunnel.underlying_netid, toobig)

    # Check that the packet too big reduced the MTU.
    routes = self.iproute.GetRoutes(tunnel.remote, 0, tunnel.underlying_netid, None)
    self.assertEquals(1, len(routes))
    rtmsg, attributes = routes[0]
    self.assertEquals(iproute.RTN_UNICAST, rtmsg.type)
    self.assertEquals(packets.PTB_MTU, attributes["RTA_METRICS"]["RTAX_MTU"])

    # Clear PMTU information so that future tests don't have to worry about it.
    self.InvalidateDstCache(version, tunnel.underlying_netid)

  def CheckTunnelInputOutput(self):
    """Test packet input and output over a Virtual Tunnel Interface."""
    for i in xrange(3 * len(self.tunnels.values())):
      tunnel = random.choice(self.tunnels.values())
      self._CheckTunnelInputOutput(tunnel, 4)
      self._CheckTunnelInputOutput(tunnel, 6)


@unittest.skipUnless(net_test.LINUX_VERSION >= (3, 18, 0), "VTI Unsupported")
class XfrmVtiTest(XfrmTunnelBase):

  INTERFACE_CLASS = VtiInterface

  def testVtiInputOutput(self):
    self.CheckTunnelInputOutput()


@unittest.skipUnless(HAVE_XFRM_INTERFACES, "XFRM interfaces unsupported")
class XfrmInterfaceTest(XfrmTunnelBase):

  INTERFACE_CLASS = XfrmInterface

  def testXfrmiInputOutput(self):
    self.CheckTunnelInputOutput()


if __name__ == "__main__":
  InjectTests()
  unittest.main()
