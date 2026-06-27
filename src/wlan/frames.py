"""802.11 frame builders using scapy Dot11."""

import struct
from scapy.all import RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11AssoResp
from scapy.all import Dot11ProbeReq, Dot11Deauth, Dot11Disas, Dot11ReassoReq

from src.wlan.ie import IE


def _dot11_header(subtype: int, type: int = 0, sender: str = "",
                  receiver: str = "", bssid: str = "", seq_num: int = 0):
    return Dot11(
        type=type,
        subtype=subtype,
        FCfield=0,
        addr1=receiver,
        addr2=sender,
        addr3=bssid,
        SC=seq_num << 4,
    )


def build_auth_frame(sender: str, receiver: str, bssid: str,
                     seq_num: int = 0, algo: int = 0,
                     seq: int = 1, status: int = 0) -> bytes:
    dot11 = _dot11_header(11, 0, sender, receiver, bssid, seq_num)
    auth = Dot11Auth(algo=algo, seqnum=seq, status=status)
    return bytes(RadioTap() / dot11 / auth)


def build_assoc_req_frame(sender: str, receiver: str, bssid: str,
                          ssid: str, capabilities: int = 0x0431,
                          rates: list[int] | None = None,
                          ies: list[IE] | None = None,
                          seq_num: int = 0) -> bytes:
    if rates is None:
        rates = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]
    dot11 = _dot11_header(0, 0, sender, receiver, bssid, seq_num)
    ies_bytes = b"".join(ie.pack() for ie in (ies or []))
    assoc = Dot11AssoReq(cap=capabilities, listen_interval=10) / (
        IE(id=0, body=ssid.encode()).pack() + IE(id=1, body=bytes(rates)).pack() + ies_bytes
    )
    return bytes(RadioTap() / dot11 / assoc)


def build_deauth_frame(sender: str, receiver: str, bssid: str,
                       reason: int = 3, seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(12, 0, sender, receiver, bssid, seq_num)
    deauth = Dot11Deauth(reason=reason)
    return bytes(RadioTap() / dot11 / deauth)


def build_disassoc_frame(sender: str, receiver: str, bssid: str,
                         reason: int = 8, seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(10, 0, sender, receiver, bssid, seq_num)
    disas = Dot11Disas(reason=reason)
    return bytes(RadioTap() / dot11 / disas)


def build_reassoc_req_frame(sender: str, receiver: str, bssid: str,
                            ssid: str, current_ap: str = "",
                            capabilities: int = 0x1104,
                            rates: list[int] | None = None,
                            ies: list[IE] | None = None,
                            seq_num: int = 0) -> bytes:
    """Build 802.11 Reassociation Request frame (type=0, subtype=2).

    Args:
        sender: STA MAC (addr2)
        receiver: Target AP MAC (addr1)
        bssid: BSSID (addr3)
        ssid: Target SSID
        current_ap: Currently associated AP MAC, defaults to receiver
        capabilities: Capability Information field
        rates: Supported Rates list, defaults to 802.11g rates
        ies: Additional Information Elements
        seq_num: Sequence number
    """
    if rates is None:
        rates = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]
    if not current_ap:
        current_ap = receiver
    dot11 = _dot11_header(2, 0, sender, receiver, bssid, seq_num)
    ies_bytes = b"".join(ie.pack() for ie in (ies or []))
    reassoc = Dot11ReassoReq(cap=capabilities, listen_interval=10,
                             current_AP=current_ap) / (
        IE(id=0, body=ssid.encode()).pack() + IE(id=1, body=bytes(rates)).pack() + ies_bytes
    )
    return bytes(RadioTap() / dot11 / reassoc)


def build_probe_req_frame(sender: str, receiver: str, bssid: str,
                          ssid: str = "", seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(4, 0, sender, receiver, bssid, seq_num)
    probe = Dot11ProbeReq() / IE(id=0, body=ssid.encode()).pack()
    return bytes(RadioTap() / dot11 / probe)


def build_null_data_frame(sender: str, receiver: str, bssid: str,
                          seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(4, 2, sender, receiver, bssid, seq_num)
    return bytes(RadioTap() / dot11)


# ═══════════════════════════════════════════════════════════════
# PHY-aware convenience wrappers (auto-resolve rate IEs via rates.py)
# These provide the simpler API from RUN/scapy on top of the
# explicit IE-based builders above.
# ═══════════════════════════════════════════════════════════════

from src.wlan.rates import common_ies, _stack_ies, DEFAULT_PHY as _DEFAULT_PHY  # noqa: E402


def build_probe_req(sta: str, ssid: str = "",
                    phy: str = _DEFAULT_PHY) -> RadioTap:
    """Build Probe Request with PHY-aware rate IEs (convenience wrapper).

    Args:
        sta: STA MAC (addr2)
        ssid: Target SSID, empty for broadcast probe
        phy: PHY type ("b", "g", "a")
    """
    dot11 = Dot11(type=0, subtype=4,
                  addr1="ff:ff:ff:ff:ff:ff", addr2=sta,
                  addr3="ff:ff:ff:ff:ff:ff")
    return _stack_ies(RadioTap() / dot11 / Dot11ProbeReq(), common_ies(ssid, phy))


def build_auth_req(sta: str, bssid: str,
                   algo: int = 0, seqnum: int = 1,
                   status: int = 0) -> RadioTap:
    """Build Authentication frame (convenience wrapper).

    Args:
        sta: STA MAC (addr2)
        bssid: AP BSSID (addr1, addr3)
        algo: Auth algorithm (0=Open, 1=Shared Key)
        seqnum: Auth sequence number
        status: Status code
    """
    dot11 = Dot11(type=0, subtype=11,
                  addr1=bssid, addr2=sta, addr3=bssid)
    return RadioTap() / dot11 / Dot11Auth(algo=algo, seqnum=seqnum, status=status)


def build_assoc_req(sta: str, bssid: str, ssid: str,
                    cap: int = 0x1104, listen_interval: int = 10,
                    phy: str = _DEFAULT_PHY) -> RadioTap:
    """Build Association Request with PHY-aware rate IEs (convenience wrapper).

    Args:
        sta: STA MAC (addr2)
        bssid: AP BSSID (addr1, addr3)
        ssid: Target SSID
        cap: Capability Information field
        listen_interval: Listen Interval
        phy: PHY type ("b", "g", "a")
    """
    dot11 = Dot11(type=0, subtype=0,
                  addr1=bssid, addr2=sta, addr3=bssid)
    body = Dot11AssoReq(cap=cap, listen_interval=listen_interval)
    return _stack_ies(RadioTap() / dot11 / body, common_ies(ssid, phy))


def build_reassoc_req(sta: str, bssid: str, ssid: str,
                      current_ap: str = "",
                      cap: int = 0x1104,
                      phy: str = _DEFAULT_PHY) -> RadioTap:
    """Build Reassociation Request with PHY-aware rate IEs (convenience wrapper).

    Args:
        sta: STA MAC (addr2)
        bssid: Target AP BSSID (addr1, addr3)
        ssid: Target SSID
        current_ap: Currently associated AP MAC, defaults to bssid
        cap: Capability Information field
        phy: PHY type ("b", "g", "a")
    """
    dot11 = Dot11(type=0, subtype=2,
                  addr1=bssid, addr2=sta, addr3=bssid)
    body = Dot11ReassoReq(
        cap=cap, listen_interval=10,
        current_AP=current_ap if current_ap else bssid,
    )
    return _stack_ies(RadioTap() / dot11 / body, common_ies(ssid, phy))


def build_deauth(src: str, dst: str,
                 bssid: str = "", reason: int = 1) -> RadioTap:
    """Build Deauthentication frame (convenience wrapper).

    Args:
        src: Source MAC (addr2, sender)
        dst: Destination MAC (addr1, receiver)
        bssid: BSSID (addr3), defaults to src
        reason: Reason Code (default 1 = Unspecified)
    """
    if not bssid:
        bssid = src
    dot11 = Dot11(type=0, subtype=12,
                  addr1=dst, addr2=src, addr3=bssid)
    return RadioTap() / dot11 / Dot11Deauth(reason=reason)


def build_disassoc(src: str, dst: str,
                   bssid: str = "", reason: int = 1) -> RadioTap:
    """Build Disassociation frame (convenience wrapper).

    Args:
        src: Source MAC (addr2, sender)
        dst: Destination MAC (addr1, receiver)
        bssid: BSSID (addr3), defaults to src
        reason: Reason Code (default 1 = Unspecified)
    """
    if not bssid:
        bssid = src
    dot11 = Dot11(type=0, subtype=10,
                  addr1=dst, addr2=src, addr3=bssid)
    return RadioTap() / dot11 / Dot11Disas(reason=reason)
