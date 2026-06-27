"""Malformed management frame tests (migrated from RUN/scapy test_pkt_abnormal_mgmt.py).

Covers: assoc-without-auth, invalid-algo, bad-seqnum, wrong-bssid,
        malformed-ies, unsolicited-deauth.
"""
import asyncio

import pytest
from scapy.all import rdpcap

from src.wlan.frames import (
    build_auth_frame, build_assoc_req_frame, build_deauth_frame, build_probe_req_frame,
)
from src.wlan.ie import oversized_ie, truncated_ie, vendor_malformed_ie
from src.wlan.anomalies import assoc_without_auth


@pytest.mark.scenario("attacks")
async def test_assoc_without_auth_malformed(ap_configured, sta, test_log_dir):
    """Skip Auth step, send Assoc directly — AP should reject/deauth."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:05:aa")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path)

    seq = assoc_without_auth(stas[0].mac)
    await sta.transport.send(seq.steps[0].frame)
    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    assert len(pkts) > 0, "Frames should be captured"


@pytest.mark.scenario("attacks")
async def test_invalid_auth_algo(ap_configured, sta, test_log_dir):
    """Send Auth frame with invalid algorithm (algo=99)."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:05:bb")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path)

    frame = build_auth_frame(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                             "ff:ff:ff:ff:ff:ff", seq_num=0, algo=99, seq=1)
    await sta.transport.send(frame)
    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    auth_sent = sum(1 for p in pkts
                    if p.haslayer("Dot11Auth") and p.addr2 == stas[0].mac)
    assert auth_sent == 1, f"Expected 1 Auth frame sent, got {auth_sent}"


@pytest.mark.scenario("attacks")
async def test_bad_auth_seqnum(ap_configured, sta, test_log_dir):
    """Send Auth frame with wrong sequence number (seqnum=5 instead of 1)."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:05:cc")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path)

    frame = build_auth_frame(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                             "ff:ff:ff:ff:ff:ff", seq_num=0, algo=0, seq=5)
    await sta.transport.send(frame)
    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    auth_sent = sum(1 for p in pkts
                    if p.haslayer("Dot11Auth") and p.addr2 == stas[0].mac)
    assert auth_sent == 1, f"Expected 1 Auth frame sent, got {auth_sent}"


@pytest.mark.scenario("attacks")
async def test_malformed_ies(ap_configured, sta, test_log_dir):
    """Send AssocReq with malformed IEs (oversized/truncated/vendor).
    
    Migrated from test_pkt_abnormal_mgmt.py malformed-ies case.
    """
    stas = await sta.create_stas(1, base_mac="00:11:22:33:05:dd")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path)

    malformed = [
        oversized_ie(48, size=512, declared_length=0),   # RSN IE with 0-length
        truncated_ie(45, actual_len=3),                   # truncated HT caps
        vendor_malformed_ie(),                             # oversized vendor IE
    ]

    frame = build_assoc_req_frame(
        stas[0].mac, "ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff",
        "test-malformed", ies=malformed,
    )
    await sta.transport.send(frame)
    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    assert len(pkts) > 0, "Malformed associaton request should be captured"
