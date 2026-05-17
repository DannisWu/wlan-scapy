"""L3 protocol packet builders — ARP, ICMP, DHCP, NDP."""

import ipaddress

from scapy.all import (
    Ether, ARP, IP, ICMP, IPv6, ICMPv6ND_NS, ICMPv6ND_NA,
)
from scapy.all import BOOTP, DHCP, UDP


def build_arp_request(src_mac: str, src_ip: str, dst_ip: str) -> bytes:
    return bytes(Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op=1, hwsrc=src_mac, psrc=src_ip,
                     hwdst="00:00:00:00:00:00", pdst=dst_ip))


def build_arp_reply(src_mac: str, src_ip: str,
                    dst_mac: str, dst_ip: str) -> bytes:
    return bytes(Ether(src=src_mac, dst=dst_mac) /
                 ARP(op=2, hwsrc=src_mac, psrc=src_ip,
                     hwdst=dst_mac, pdst=dst_ip))


def build_icmp_echo(src_ip: str, dst_ip: str,
                    id_: int = 1, seq: int = 1,
                    payload_size: int = 56) -> bytes:
    return bytes(Ether() /
                 IP(src=src_ip, dst=dst_ip) /
                 ICMP(type=8, id=id_, seq=seq) /
                 ("\x00" * payload_size))


def build_dhcp_discover(src_mac: str, xid: int = 0x12345678) -> bytes:
    return bytes(
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=src_mac.replace(":", "").encode(), xid=xid) /
        DHCP(options=[("message-type", "discover"), "end"])
    )


def build_dhcp_request(src_mac: str, requested_ip: str,
                       xid: int = 0x12345678) -> bytes:
    return bytes(
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=src_mac.replace(":", "").encode(), xid=xid) /
        DHCP(options=[
            ("message-type", "request"),
            ("requested_addr", requested_ip),
            "end",
        ])
    )


def build_nd_solicit(src_mac: str, src_ip6: str,
                     target_ip6: str) -> bytes:
    # Compute solicited-node multicast from target's last 24 bits
    tgt = ipaddress.IPv6Address(target_ip6)
    last24 = tgt.packed[-3:]
    sn_mcast = (
        f"ff02::1:ff{last24[0]:02x}:"
        f"{last24[1]:02x}{last24[2]:02x}"
    )
    # Multicast MAC takes the last 4 bytes of the solicited-node address;
    # byte 12 is always 0xff in the solicited-node prefix.
    sn_mac = (
        f"33:33:ff:{last24[0]:02x}:{last24[1]:02x}:{last24[2]:02x}"
    )
    return bytes(
        Ether(src=src_mac, dst=sn_mac) /
        IPv6(src=src_ip6, dst=sn_mcast) /
        ICMPv6ND_NS(tgt=target_ip6)
    )
