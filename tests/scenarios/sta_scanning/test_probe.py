"""Probe Request scanning tests (migrated from RUN/scapy test_sta_probe_request.py)."""
import asyncio

import pytest
from scapy.all import rdpcap

from src.devices.sta import SecurityParams


def _pcap_has_probe_req(pcap_path: str, sta_mac: str, count: int = 1) -> bool:
    pkts = rdpcap(str(pcap_path))
    matches = sum(1 for p in pkts
                  if p.haslayer("Dot11ProbeReq") and p.addr2 == sta_mac)
    return matches >= count


@pytest.mark.scenario("sta_scanning")
async def test_probe_request_broadcast(ap_configured, sta, test_log_dir):
    """Send broadcast Probe Request and verify via pcap."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:01:11")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")

    # Send a Probe Request via the transport directly
    from src.wlan.frames import build_probe_req_frame
    frame = build_probe_req_frame(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                                  "ff:ff:ff:ff:ff:ff", "test-probe")
    await sta.transport.send(frame)
    await asyncio.sleep(0.5)
    await sta.stop_capture()

    assert _pcap_has_probe_req(pcap_path, stas[0].mac), (
        "Probe Request not captured"
    )


@pytest.mark.scenario("sta_scanning")
async def test_probe_request_targeted_ssid(ap_configured, sta, test_log_dir):
    """Send targeted Probe Request with specific SSID."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:01:22")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")

    from src.wlan.frames import build_probe_req_frame
    frame = build_probe_req_frame(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                                  "ff:ff:ff:ff:ff:ff", "MyTargetSSID")
    await sta.transport.send(frame)
    await asyncio.sleep(0.5)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    found = False
    for p in pkts:
        if p.haslayer("Dot11ProbeReq") and p.addr2 == stas[0].mac:
            if b"MyTargetSSID" in bytes(p):
                found = True
                break
    assert found, "Targeted Probe Request with SSID not captured"
