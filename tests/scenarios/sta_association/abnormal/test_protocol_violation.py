"""Abnormal protocol violation tests -- malformed IEs, skipped steps."""

import asyncio

import pytest
from scapy.all import rdpcap

from src.wlan.anomalies import assoc_without_auth, repeated_auth


def _pcap_has_deauth(pcap_path: str, sta_mac: str) -> bool:
    pkts = rdpcap(str(pcap_path))
    for p in pkts:
        if p.haslayer("Dot11Deauth") and p.addr1 == sta_mac:
            return True
    return False


@pytest.mark.scenario("sta_association")
async def test_assoc_without_auth(ap_configured, sta, test_log_dir):
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:aa")
    pcap_path = test_log_dir / "air.pcap"
    await sta.start_capture(pcap_path)

    seq = assoc_without_auth(stas[0].mac)
    await sta.send_sequence(stas[0], seq)
    await asyncio.sleep(1)
    await sta.stop_capture()

    assert _pcap_has_deauth(pcap_path, stas[0].mac), (
        "AP should send deauth when ASSOC without AUTH"
    )


@pytest.mark.scenario("sta_association")
async def test_repeated_auth(ap_configured, sta, test_log_dir):
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:bb")
    pcap_path = test_log_dir / "air.pcap"
    await sta.start_capture(pcap_path)

    seq = repeated_auth(stas[0].mac)
    await sta.send_sequence(stas[0], seq)
    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    auth_count = sum(
        1 for p in pkts if p.haslayer("Dot11Auth") and p.addr2 == stas[0].mac
    )
    assert auth_count == 5, f"Expected 5 AUTH frames, got {auth_count}"
