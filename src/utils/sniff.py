"""Packet sniffing utilities for WLAN testing.

Provides monitor-mode capture helpers for DHCP response sniffing,
frame verification, and pcap analysis.
"""

from typing import Optional, Tuple

from scapy.all import (
    BOOTP,
    DHCP,
    Dot11,
    IP,
    UDP,
    sniff,
)


def sniff_dhcp_reply(
    iface: str,
    sta_mac: str,
    timeout: float = 3.0,
    msg_type: Optional[int] = None,
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[int]]:
    """Sniff DHCP response (Offer/Ack) on monitor interface for a given STA.

    On monitor mode, captures all 802.11 frames in the air, so AP→STA
    data frames carrying DHCP responses can be parsed to extract
    IP address, gateway, and server info.

    Args:
        iface: Monitor-mode interface name
        sta_mac: STA MAC address to filter for (addr1 must match)
        timeout: Sniff timeout in seconds (default 3s)
        msg_type: Filter by DHCP message type:
            2 = Offer, 5 = Ack, None = any

    Returns:
        (yiaddr, gateway, server_ip, dhcp_xid) — success
        (None, None, None, None) — timeout or no match
    """
    captured = {"yiaddr": None, "siaddr": None, "xid": None, "gateway": None}

    def _stop_filter(pkt) -> bool:
        """Match AP→STA DHCP response frames, extract IP and gateway."""
        if not pkt.haslayer(Dot11):
            return False
        dot11 = pkt[Dot11]
        if dot11.addr1 != sta_mac:
            return False
        if dot11.type != 2:  # Data
            return False
        if not pkt.haslayer(IP) or not pkt.haslayer(UDP):
            return False
        if pkt[UDP].sport != 67 or pkt[UDP].dport != 68:
            return False
        if not pkt.haslayer(BOOTP) or pkt[BOOTP].op != 2:  # BOOTREPLY
            return False

        # Check DHCP message type if filter specified
        if msg_type is not None and pkt.haslayer(DHCP):
            pkt_type = None
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    pkt_type = opt[1]
                    break
            if pkt_type != msg_type:
                return False  # Not the expected type, keep waiting

        # Match: extract info
        captured["yiaddr"] = pkt[BOOTP].yiaddr
        captured["siaddr"] = pkt[BOOTP].siaddr or pkt[IP].src
        captured["xid"] = pkt[BOOTP].xid

        # Extract gateway from DHCP option 3 (router)
        if pkt.haslayer(DHCP):
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "router":
                    gw = opt[1]
                    if isinstance(gw, list) and len(gw) > 0:
                        captured["gateway"] = gw[0]
                    elif isinstance(gw, str):
                        captured["gateway"] = gw
                    break

        return True

    try:
        sniff(
            iface=iface, stop_filter=_stop_filter, timeout=timeout,
            store=False, quiet=True,
        )
    except Exception:
        return None, None, None, None

    if captured["yiaddr"] is not None:
        return (captured["yiaddr"], captured["gateway"],
                captured["siaddr"], captured["xid"])
    return None, None, None, None
