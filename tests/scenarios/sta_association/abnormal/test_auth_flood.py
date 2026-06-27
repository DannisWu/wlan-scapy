"""Auth flood stress tests (migrated from RUN/scapy test_sta_auth_flood.py)."""
import asyncio

import pytest
from scapy.all import rdpcap

from src.devices.sta import StaInstance


@pytest.mark.scenario("sta_association")
async def test_auth_flood_single_sta(ap_configured, sta, test_log_dir):
    """Single STA sends multiple Auth frames in a flood."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:02:11")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")

    flood_count = 10
    for i in range(flood_count):
        await sta.send_auth(stas[0], "ff:ff:ff:ff:ff:ff",
                            algo=0, seq=i + 1, status=0)
        await asyncio.sleep(0.02)

    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    auth_count = sum(1 for p in pkts
                     if p.haslayer("Dot11Auth") and p.addr2 == stas[0].mac)
    assert auth_count == flood_count, (
        f"Expected {flood_count} Auth frames, got {auth_count}"
    )


@pytest.mark.scenario("sta_association")
async def test_auth_flood_invalid_algo(ap_configured, sta, test_log_dir):
    """Auth flood with invalid authentication algorithm (algo=99)."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:02:22")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")

    for i in range(5):
        from src.wlan.frames import build_auth_frame
        frame = build_auth_frame(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                                 "ff:ff:ff:ff:ff:ff", seq_num=i, algo=99, seq=1)
        await sta.transport.send(frame)
        await asyncio.sleep(0.05)

    await asyncio.sleep(1)
    await sta.stop_capture()

    # AP should ignore or reject frames with invalid algo
    pkts = rdpcap(str(pcap_path))
    auth_sent = sum(1 for p in pkts
                    if p.haslayer("Dot11Auth") and p.addr2 == stas[0].mac)
    assert auth_sent == 5, f"Expected 5 Auth frames sent, got {auth_sent}"
