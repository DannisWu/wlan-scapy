"""802.11 frame builders using scapy Dot11."""

import struct
from scapy.all import RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11AssoResp
from scapy.all import Dot11ProbeReq, Dot11Deauth, Dot11Disas

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


def build_probe_req_frame(sender: str, receiver: str, bssid: str,
                          ssid: str = "", seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(4, 0, sender, receiver, bssid, seq_num)
    probe = Dot11ProbeReq() / IE(id=0, body=ssid.encode()).pack()
    return bytes(RadioTap() / dot11 / probe)


def build_null_data_frame(sender: str, receiver: str, bssid: str,
                          seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(4, 2, sender, receiver, bssid, seq_num)
    return bytes(RadioTap() / dot11)
