"""L4 protocol packet builders — TCP, UDP."""

from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw


def build_tcp_syn(src_mac: str = "00:11:22:33:44:01",
                  dst_mac: str = "00:11:22:33:44:02",
                  src_ip: str = "192.168.1.100",
                  dst_ip: str = "192.168.1.1",
                  sport: int = 12345, dport: int = 80,
                  seq: int = 1000, flags: str = "S") -> bytes:
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, seq=seq, flags=flags)
    )


def build_tcp_rst(src_mac: str = "00:11:22:33:44:01",
                  dst_mac: str = "00:11:22:33:44:02",
                  src_ip: str = "192.168.1.100",
                  dst_ip: str = "192.168.1.1",
                  sport: int = 12345, dport: int = 80,
                  seq: int = 1001) -> bytes:
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, seq=seq, flags="R")
    )


def build_udp(src_mac: str = "00:11:22:33:44:01",
              dst_mac: str = "00:11:22:33:44:02",
              src_ip: str = "192.168.1.100",
              dst_ip: str = "192.168.1.1",
              sport: int = 12345, dport: int = 53,
              payload: bytes = b"") -> bytes:
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=sport, dport=dport) /
        Raw(payload)
    )


def build_udp_ipv6(src_mac: str = "00:11:22:33:44:01",
                   dst_mac: str = "00:11:22:33:44:02",
                   src_ip6: str = "fe80::1",
                   dst_ip6: str = "fe80::2",
                   sport: int = 12345, dport: int = 53,
                   payload: bytes = b"") -> bytes:
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IPv6(src=src_ip6, dst=dst_ip6) /
        UDP(sport=sport, dport=dport) /
        Raw(payload)
    )
