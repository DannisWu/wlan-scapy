from scapy.all import Ether, IP, IPv6, TCP, UDP

from src.traffic.l4 import (
    build_tcp_syn,
    build_tcp_rst,
    build_udp,
    build_udp_ipv6,
)


def test_build_tcp_syn():
    pkt = Ether(build_tcp_syn())
    assert pkt[TCP].flags == "S"
    assert pkt[TCP].sport == 12345
    assert pkt[TCP].dport == 80


def test_build_tcp_rst():
    pkt = Ether(build_tcp_rst())
    assert pkt[TCP].flags == "R"
    assert pkt[TCP].seq == 1001


def test_build_udp():
    pkt = Ether(build_udp(payload=b"hello"))
    assert pkt[UDP].sport == 12345
    assert pkt[UDP].dport == 53
    assert bytes(pkt[UDP].payload) == b"hello"


def test_build_udp_ipv6():
    pkt = Ether(build_udp_ipv6(payload=b"hello"))
    assert pkt[IPv6].src == "fe80::1"
    assert pkt[UDP].dport == 53
    assert bytes(pkt[UDP].payload) == b"hello"
