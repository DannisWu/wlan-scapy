from scapy.all import Ether, ARP, ICMP, DHCP, IPv6, ICMPv6ND_NS

from src.traffic.l3 import (
    build_arp_request,
    build_arp_reply,
    build_icmp_echo,
    build_dhcp_discover,
    build_dhcp_request,
    build_nd_solicit,
)


def test_arp_request():
    pkt = Ether(build_arp_request("00:11:22:33:44:55", "192.168.1.1", "192.168.1.2"))
    assert pkt[ARP].op == 1
    assert pkt[ARP].psrc == "192.168.1.1"


def test_arp_reply():
    pkt = Ether(build_arp_reply(
        "00:11:22:33:44:55", "192.168.1.1",
        "00:aa:bb:cc:dd:ee", "192.168.1.2",
    ))
    assert pkt[ARP].op == 2
    assert pkt[ARP].psrc == "192.168.1.1"
    assert pkt[ARP].pdst == "192.168.1.2"


def test_icmp_echo():
    pkt = Ether(build_icmp_echo("10.0.0.1", "10.0.0.2"))
    assert pkt[ICMP].type == 8


def test_dhcp_discover():
    pkt = Ether(build_dhcp_discover("00:11:22:33:44:55"))
    assert pkt.dst == "ff:ff:ff:ff:ff:ff"


def test_dhcp_request():
    pkt = Ether(build_dhcp_request("00:11:22:33:44:55", "192.168.1.100"))
    assert pkt.dst == "ff:ff:ff:ff:ff:ff"
    dhcp_opts = dict(
        opt for opt in pkt[DHCP].options if isinstance(opt, tuple)
    )
    # Scapy encodes message-type as int (3 = DHCPREQUEST)
    assert dhcp_opts.get("message-type") == 3
    assert dhcp_opts.get("requested_addr") == "192.168.1.100"


def test_nd_solicit():
    pkt = Ether(build_nd_solicit(
        "00:11:22:33:44:55", "fe80::1", "fe80::2",
    ))
    assert pkt[IPv6].src == "fe80::1"
    assert pkt[ICMPv6ND_NS].tgt == "fe80::2"
    # Solicited-node multicast address for fe80::2 -> last 24 bits of ::2 = 00:00:02
    # ff02::1:ff00:0002
    assert pkt[IPv6].dst == "ff02::1:ff00:2"
    # MAC takes last 4 bytes of solicited-node: ff:00:00:02
    assert pkt.dst == "33:33:ff:00:00:02"
