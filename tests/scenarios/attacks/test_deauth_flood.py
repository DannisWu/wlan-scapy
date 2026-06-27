"""Deauth/Disassoc flood attack tests (migrated from RUN/scapy test_pkt_deauth_flood.py)."""
import asyncio

import pytest
from scapy.all import rdpcap

from src.wlan.frames import build_deauth_frame, build_disassoc_frame


@pytest.mark.scenario("attacks")
async def test_deauth_flood_single_sta(ap_configured, sta, test_log_dir):
    """Single virtual STA floods deauth frames toward AP."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:04:11")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")

    flood_count = 10
    for i in range(flood_count):
        frame = build_deauth_frame(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                                   "ff:ff:ff:ff:ff:ff", reason=1, seq_num=i)
        await sta.transport.send(frame)
        await asyncio.sleep(0.02)

    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    deauth_count = sum(1 for p in pkts
                       if p.haslayer("Dot11Deauth") and p.addr2 == stas[0].mac)
    assert deauth_count == flood_count, (
        f"Expected {flood_count} Deauth frames, got {deauth_count}"
    )


@pytest.mark.scenario("attacks")
async def test_disassoc_flood_single_sta(ap_configured, sta, test_log_dir):
    """Single virtual STA floods disassoc frames toward AP."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:04:22")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")

    flood_count = 10
    for i in range(flood_count):
        frame = build_disassoc_frame(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                                     "ff:ff:ff:ff:ff:ff", reason=3, seq_num=i)
        await sta.transport.send(frame)
        await asyncio.sleep(0.02)

    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    disassoc_count = sum(1 for p in pkts
                         if p.haslayer("Dot11Disas") and p.addr2 == stas[0].mac)
    assert disassoc_count == flood_count, (
        f"Expected {flood_count} Disassoc frames, got {disassoc_count}"
    )


@pytest.mark.scenario("attacks")
async def test_spoofed_ap_deauth(ap_configured, sta, test_log_dir):
    """Spoof AP BSSID and broadcast deauth to all STAs."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:04:33")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path)

    # Spoof as if the AP itself is sending deauth
    spoofed_frame = build_deauth_frame(
        "ff:ff:ff:ff:ff:ff",  # spoofed AP MAC (sender)
        "ff:ff:ff:ff:ff:ff",  # broadcast (receiver)
        "ff:ff:ff:ff:ff:ff",  # BSSID
        reason=7,  # Class 3 nonassociated
    )
    await sta.transport.send(spoofed_frame)
    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    assert len(pkts) > 0, "Spoofed deauth should be captured"
