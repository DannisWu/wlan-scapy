from scapy.all import Ether, ARP, ICMP

from src.traffic.l3 import build_arp_request, build_icmp_echo, build_dhcp_discover


def test_arp_request():
    pkt = Ether(build_arp_request("00:11:22:33:44:55", "192.168.1.1", "192.168.1.2"))
    assert pkt[ARP].op == 1
    assert pkt[ARP].psrc == "192.168.1.1"


def test_icmp_echo():
    pkt = Ether(build_icmp_echo("10.0.0.1", "10.0.0.2"))
    assert pkt[ICMP].type == 8


def test_dhcp_discover():
    pkt = Ether(build_dhcp_discover("00:11:22:33:44:55"))
    assert pkt.dst == "ff:ff:ff:ff:ff:ff"
