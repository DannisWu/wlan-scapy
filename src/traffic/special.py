"""Special packet builders — jumbo, fragmentation, multicast/broadcast."""

import ipaddress

from scapy.all import Ether, IP, IPv6, ICMP, Raw, fragment, fragment6


def build_jumbo_packet(src_mac: str = "00:11:22:33:44:01",
                       dst_mac: str = "00:11:22:33:44:02",
                       src_ip: str = "192.168.1.100",
                       dst_ip: str = "192.168.1.1",
                       size: int = 9000) -> bytes:
    payload_size = size - 14 - 20 - 8
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip, flags="DF") /
        ICMP() /
        Raw(b"\x00" * max(0, payload_size))
    )


def build_ipv4_fragments(src_mac: str = "00:11:22:33:44:01",
                         dst_mac: str = "00:11:22:33:44:02",
                         src_ip: str = "192.168.1.100",
                         dst_ip: str = "192.168.1.1",
                         payload: bytes | None = None,
                         frag_size: int = 1480) -> list[bytes]:
    if payload is None:
        payload = b"A" * 4000
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP() / Raw(payload)
    frags = fragment(pkt, fragsize=frag_size)
    return [bytes(f) for f in frags]


def build_ipv6_fragments(src_mac: str = "00:11:22:33:44:01",
                         dst_mac: str = "00:11:22:33:44:02",
                         src_ip6: str = "fe80::1",
                         dst_ip6: str = "fe80::2",
                         payload: bytes | None = None,
                         frag_size: int = 1280) -> list[bytes]:
    if payload is None:
        payload = b"A" * 3000
    pkt = (Ether(src=src_mac, dst=dst_mac) /
           IPv6(src=src_ip6, dst=dst_ip6) /
           ICMP() /
           Raw(payload))
    frags = fragment6(pkt, fragSize=frag_size)
    return [bytes(f) for f in frags]


def build_multicast_ipv4(src_mac: str = "00:11:22:33:44:01",
                         group: str = "224.0.0.1",
                         dst_mac: str | None = None,
                         payload: bytes = b"test") -> bytes:
    if dst_mac is None:
        group_ip = ipaddress.IPv4Address(group)
        dst_mac = "01:00:5e:" + ":".join(
            f"{(b & 0x7f):02x}" for b in group_ip.packed[-3:]
        )
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IP(src="192.168.1.100", dst=group) /
        Raw(payload)
    )


def build_broadcast_ipv4(src_mac: str = "00:11:22:33:44:01",
                         payload: bytes = b"test") -> bytes:
    return bytes(
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="192.168.1.100", dst="255.255.255.255") /
        Raw(payload)
    )


def build_multicast_ipv6(src_mac: str = "00:11:22:33:44:01",
                         group: str = "ff02::1",
                         dst_mac: str | None = None,
                         payload: bytes = b"test") -> bytes:
    if dst_mac is None:
        group_ip = ipaddress.IPv6Address(group)
        last4 = group_ip.packed[-4:]
        dst_mac = (
            f"33:33:{last4[0]:02x}:{last4[1]:02x}:"
            f"{last4[2]:02x}:{last4[3]:02x}"
        )
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IPv6(src="fe80::1", dst=group) /
        Raw(payload)
    )
