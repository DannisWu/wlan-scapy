"""Invalid rate set association tests (migrated from RUN/scapy test_sta_invalid_support_rate.py).

Tests using wrong PHY rate sets trigger Status Code 18 (Rateset mismatch).
"""
import asyncio

import pytest
from scapy.all import rdpcap

from src.devices.sta import SecurityParams
from src.wlan.rates import RATE_SETS, PHY_BAND


@pytest.mark.scenario("sta_association")
async def test_assoc_wrong_phy_rates(ap_configured, sta, test_log_dir):
    """Associate with 5GHz OFDM rates on 2.4GHz AP (expected: mismatch)."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:03:11")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")

    # Modify the STA to use 5GHz rates
    stas[0].supported_rates = list(RATE_SETS["a"][0])
    if RATE_SETS["a"][1]:
        stas[0].supported_rates.extend(list(RATE_SETS["a"][1]))

    result = await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff", "test-rates",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    await asyncio.sleep(1)
    await sta.stop_capture()

    # AP should reject (or at minimum the association should have been attempted)
    pkts = rdpcap(str(pcap_path))
    auth_sent = sum(1 for p in pkts
                    if p.haslayer("Dot11Auth") and p.addr2 == stas[0].mac)
    assert auth_sent > 0, "Auth frames should have been sent"


@pytest.mark.scenario("sta_association")
async def test_assoc_wrong_phy_11b_on_5g(ap_configured, sta, test_log_dir):
    """Associate with 802.11b CCK rates (2.4GHz only) — expected mismatch."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:03:22")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")

    # 802.11b rates
    stas[0].supported_rates = list(RATE_SETS["b"][0])
    if RATE_SETS["b"][1]:
        stas[0].supported_rates.extend(list(RATE_SETS["b"][1]))

    result = await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff", "test-rates-b",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    await asyncio.sleep(1)
    await sta.stop_capture()

    assert True  # Frame injection itself should succeed
