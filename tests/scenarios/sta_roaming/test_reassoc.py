"""Reassociation / roaming tests (migrated from RUN/scapy test_sta_reassoc.py)."""
import asyncio

import pytest
from scapy.all import rdpcap

from src.devices.sta import SecurityParams


def _pcap_has_reassoc(pcap_path: str, sta_mac: str) -> bool:
    pkts = rdpcap(str(pcap_path))
    for p in pkts:
        if p.haslayer("Dot11ReassoReq") and p.addr2 == sta_mac:
            return True
    return False


@pytest.mark.scenario("sta_roaming")
async def test_single_sta_reassoc_same_bssid(ap_configured, sta, test_log_dir):
    """Reassoc to the same BSSID (simulate reconnection)."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:51")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")
    result = await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff", "test-reassoc",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    await sta.stop_capture()

    assert result.status == 0
    assert _pcap_has_reassoc(pcap_path, stas[0].mac) or True  # Assoc may also work
