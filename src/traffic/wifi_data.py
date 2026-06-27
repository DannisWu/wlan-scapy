"""DHCP / ARP / ICMP frame builders over 802.11 (data-plane injection).

These frame builders construct fully-encapsulated RadioTap frames
suitable for direct injection on a monitor-mode interface.
"""

import random
from typing import Optional

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
    Dot11,
    ICMP,
    IP,
    LLC,
    RadioTap,
    SNAP,
    UDP,
)


def _mac_to_bytes(mac: str) -> bytes:
    """Convert MAC address string to 6 bytes."""
    return bytes.fromhex(mac.replace(":", ""))


def _llc_snap(ethertype: int):
    """Return LLC/SNAP encapsulation layer.

    ethertype: 0x0800 = IPv4, 0x0806 = ARP.
    """
    return LLC(dsap=0xAA, ssap=0xAA, ctrl=0x03) / SNAP(OUI=0x000000, code=ethertype)


def build_dhcp_discover(
    sta: str,
    bssid: str,
    transaction_id: Optional[int] = None,
) -> RadioTap:
    """Build DHCP Discover over 802.11 data frame (STA→AP).

    Frame: RadioTap / Dot11(Data,to-DS) / LLC / SNAP / IP / UDP / BOOTP / DHCP

    Args:
        sta: STA MAC address
        bssid: AP BSSID
        transaction_id: DHCP transaction ID, random if None
    """
    if transaction_id is None:
        transaction_id = random.randint(0, 0xFFFFFFFF)

    dot11 = Dot11(
        type=2, subtype=0, FCfield="to-DS",
        addr1=bssid, addr2=sta, addr3="ff:ff:ff:ff:ff:ff",
    )
    dhcp_layer = (
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=_mac_to_bytes(sta), xid=transaction_id) /
        DHCP(options=[
            ("message-type", "discover"),
            ("param_req_list", [1, 3, 6, 15, 28, 42]),
            "end",
        ])
    )
    return RadioTap() / dot11 / _llc_snap(0x0800) / dhcp_layer


def build_dhcp_request(
    sta: str,
    bssid: str,
    transaction_id: Optional[int] = None,
) -> RadioTap:
    """Build DHCP Request over 802.11 data frame (STA→AP).

    Args:
        sta: STA MAC address
        bssid: AP BSSID
        transaction_id: DHCP transaction ID, random if None
    """
    if transaction_id is None:
        transaction_id = random.randint(0, 0xFFFFFFFF)

    dot11 = Dot11(
        type=2, subtype=0, FCfield="to-DS",
        addr1=bssid, addr2=sta, addr3="ff:ff:ff:ff:ff:ff",
    )
    dhcp_layer = (
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=_mac_to_bytes(sta), xid=transaction_id) /
        DHCP(options=[
            ("message-type", "request"),
            ("param_req_list", [1, 3, 6, 15, 28, 42]),
            "end",
        ])
    )
    return RadioTap() / dot11 / _llc_snap(0x0800) / dhcp_layer


def build_arp_request(
    sta: str,
    bssid: str,
    target_ip: str = "192.168.1.1",
    sender_ip: str = "0.0.0.0",
) -> RadioTap:
    """Build ARP Request over 802.11 data frame (STA→AP).

    Frame: RadioTap / Dot11(Data,to-DS) / LLC / SNAP / ARP

    Args:
        sta: STA MAC (hwsrc)
        bssid: AP BSSID
        target_ip: Target IP (e.g. gateway IP)
        sender_ip: Sender IP (default 0.0.0.0 for unknown)
    """
    dot11 = Dot11(
        type=2, subtype=0, FCfield="to-DS",
        addr1=bssid, addr2=sta, addr3="ff:ff:ff:ff:ff:ff",
    )
    arp_layer = ARP(
        op=1,  # who-has (request)
        hwsrc=sta,
        psrc=sender_ip,
        hwdst="00:00:00:00:00:00",
        pdst=target_ip,
    )
    return RadioTap() / dot11 / _llc_snap(0x0806) / arp_layer


def build_icmp_echo(
    sta: str,
    bssid: str,
    src_ip: str,
    dst_ip: str,
    seq: int = 1,
    ident: Optional[int] = None,
) -> RadioTap:
    """Build ICMP Echo Request (ping) over 802.11 data frame (STA→AP).

    Frame: RadioTap / Dot11(Data,to-DS) / LLC / SNAP / IP / ICMP Echo

    Args:
        sta: STA MAC
        bssid: AP BSSID
        src_ip: Source IP (STA acquired address)
        dst_ip: Destination IP (e.g. gateway)
        seq: ICMP sequence number
        ident: ICMP identifier, random if None
    """
    if ident is None:
        ident = random.randint(0, 0xFFFF)

    dot11 = Dot11(
        type=2, subtype=0, FCfield="to-DS",
        addr1=bssid, addr2=sta, addr3="ff:ff:ff:ff:ff:ff",
    )
    ip_icmp = (
        IP(src=src_ip, dst=dst_ip) /
        ICMP(type=8, code=0, id=ident, seq=seq)
    )
    return RadioTap() / dot11 / _llc_snap(0x0800) / ip_icmp
