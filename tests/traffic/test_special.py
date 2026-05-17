from scapy.all import Ether, IP, IPv6, ICMP, Raw

from src.traffic.special import (
    build_jumbo_packet,
    build_ipv4_fragments,
    build_multicast_ipv4,
    build_broadcast_ipv4,
)


def test_build_jumbo_packet():
    pkt = Ether(build_jumbo_packet(size=9000))
    assert pkt[IP].flags == "DF"
    assert len(pkt) == 9000


def test_build_ipv4_fragments():
    frags = build_ipv4_fragments(frag_size=1480)
    assert len(frags) >= 2
    for f in frags:
        assert len(f) <= 1514  # 14 (Ether) + 20 (IP) + 1480


def test_build_multicast_ipv4():
    pkt = Ether(build_multicast_ipv4(group="224.0.0.1"))
    assert pkt[IP].dst == "224.0.0.1"
    # MAC should be computed: 01:00:5e:00:00:01
    assert pkt.dst == "01:00:5e:00:00:01"


def test_build_multicast_ipv4_with_dst_mac():
    pkt = Ether(build_multicast_ipv4(group="239.192.1.1",
                                      dst_mac="01:00:5e:40:01:01"))
    assert pkt.dst == "01:00:5e:40:01:01"


def test_build_broadcast_ipv4():
    pkt = Ether(build_broadcast_ipv4())
    assert pkt.dst == "ff:ff:ff:ff:ff:ff"
    assert pkt[IP].dst == "255.255.255.255"


def test_build_multicast_ipv6():
    from src.traffic.special import build_multicast_ipv6
    pkt = Ether(build_multicast_ipv6(group="ff02::1"))
    assert pkt[IPv6].dst == "ff02::1"
    # MAC is last 4 bytes of ff02::1 = 00:00:00:01
    assert pkt.dst == "33:33:00:00:00:01"
