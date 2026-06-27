"""Truncated frame tests (migrated from RUN/scapy test_pkt_abnormal_len.py).

Tests 4 types of truncated frames below protocol minimum lengths:
  - control-short:   < 16 bytes (normal RTS=16)
  - mgmt-short:      < 22 bytes (normal header=24)
  - data-short:      < 22 bytes (normal header=24)
  - qos-data-short:  < 30 bytes (normal header+QoS+HT=30)
"""
import asyncio
import struct

import pytest
from scapy.all import RadioTap, Raw, rdpcap


# 802.11 Frame Control field (2 bytes) common combinations
FC_CONTROL_RTS = 0x00B4      # type=1 subtype=11 (RTS)
FC_MGMT_AUTH = 0x00B0       # type=0 subtype=11 (Auth)
FC_DATA_TODS = 0x0802        # type=2 subtype=0 (Data), to-DS=1
FC_QOS_DATA_TODS = 0x8802    # type=2 subtype=8 (QoS Data), to-DS=1


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def _build_control_short(sta: str, bssid: str) -> bytes:
    """Truncated control frame (< 16 bytes). RTS truncated from 16 to 14."""
    raw = (
        struct.pack("<H", FC_CONTROL_RTS) +
        struct.pack("<H", 0x0000) +           # Duration
        _mac_bytes(bssid) +                    # RA
        _mac_bytes(sta)[:4]                    # TA truncated (6→4)
    )
    return bytes(RadioTap() / Raw(load=raw))


def _build_mgmt_short(sta: str, bssid: str) -> bytes:
    """Truncated management frame (< 22 bytes). Auth header 24→20."""
    full = (
        struct.pack("<H", FC_MGMT_AUTH) +
        struct.pack("<H", 0x0000) +           # Duration
        _mac_bytes(bssid) +                    # DA (addr1)
        _mac_bytes(sta) +                      # SA (addr2)
        _mac_bytes(bssid) +                    # BSSID (addr3)
        struct.pack("<H", 0x0000)              # Sequence Control
    )
    return bytes(RadioTap() / Raw(load=full[:20]))


def _build_data_short(sta: str, bssid: str) -> bytes:
    """Truncated non-QoS data frame (< 22 bytes)."""
    full = (
        struct.pack("<H", FC_DATA_TODS) +
        struct.pack("<H", 0x0000) +
        _mac_bytes(bssid) +                    # Addr1 (DA)
        _mac_bytes(sta) +                      # Addr2 (SA)
        _mac_bytes(bssid) +                    # Addr3 (BSSID)
        struct.pack("<H", 0x0000)
    )
    return bytes(RadioTap() / Raw(load=full[:20]))


def _build_qos_data_short(sta: str, bssid: str) -> bytes:
    """Truncated QoS data frame (< 30 bytes). 30→28."""
    full = (
        struct.pack("<H", FC_QOS_DATA_TODS) +
        struct.pack("<H", 0x0000) +
        _mac_bytes(bssid) +                    # Addr1
        _mac_bytes(sta) +                      # Addr2
        _mac_bytes(bssid) +                    # Addr3
        struct.pack("<H", 0x0000) +            # Seq Ctrl
        struct.pack("<H", 0x0000) +            # QoS Control (2 bytes)
        struct.pack("<I", 0x00000000)           # HT Control (4 bytes)
    )
    return bytes(RadioTap() / Raw(load=full[:28]))


TRUNCATED_BUILDERS = {
    "control-short": _build_control_short,
    "mgmt-short": _build_mgmt_short,
    "data-short": _build_data_short,
    "qos-data-short": _build_qos_data_short,
}

THRESHOLDS = {
    "control-short": 16,
    "mgmt-short": 22,
    "data-short": 22,
    "qos-data-short": 30,
}


@pytest.mark.scenario("attacks")
@pytest.mark.parametrize("frame_type", list(TRUNCATED_BUILDERS.keys()))
async def test_truncated_frame(ap_configured, sta, test_log_dir,
                                frame_type: str):
    """Send truncated frames below protocol minimum length."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:06:11")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path)

    builder = TRUNCATED_BUILDERS[frame_type]
    frame = builder(stas[0].mac, "ff:ff:ff:ff:ff:ff")
    threshold = THRESHOLDS[frame_type]

    # Verify the frame body is below threshold
    body_len = len(frame) - len(RadioTap())
    assert body_len < threshold, (
        f"{frame_type}: body_len={body_len} >= threshold={threshold}"
    )

    await sta.transport.send(frame)
    await asyncio.sleep(0.5)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    assert len(pkts) > 0, f"Truncated frame ({frame_type}) should be captured"
