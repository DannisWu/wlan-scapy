"""Full STA association lifecycle tests (migrated from RUN/scapy test_sta_assoc_normal.py).

Covers: Probe → Auth → Assoc → [optional: DHCP → ARP → Ping → Deauth → offline].
"""
import asyncio

import pytest
from scapy.all import rdpcap

from src.devices.sta import SecurityParams
from src.traffic.wifi_data import (
    build_dhcp_discover, build_dhcp_request,
    build_arp_request, build_icmp_echo,
)


def _pcap_has_auth(pcap_path: str, sta_mac: str) -> bool:
    pkts = rdpcap(str(pcap_path))
    for p in pkts:
        if p.haslayer("Dot11Auth") and p.addr2 == sta_mac:
            return True
    return False


def _pcap_has_assoc(pcap_path: str, sta_mac: str) -> bool:
    pkts = rdpcap(str(pcap_path))
    for p in pkts:
        if p.haslayer("Dot11AssoReq") and p.addr2 == sta_mac:
            return True
    return False


@pytest.mark.scenario("sta_association")
async def test_sta_full_assoc_mgmt_only(ap_configured, sta, test_log_dir):
    """Basic STA association: Probe → Auth → Assoc (management plane only)."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:07:11")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")

    # Step 1: Probe Request
    from src.wlan.frames import build_probe_req_frame
    probe = build_probe_req_frame(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                                  "ff:ff:ff:ff:ff:ff", "test-cylce")
    await sta.transport.send(probe)
    await asyncio.sleep(0.1)

    # Step 2: Auth
    await sta.send_auth(stas[0], "ff:ff:ff:ff:ff:ff", algo=0, seq=1, status=0)
    await asyncio.sleep(0.2)

    # Step 3: Assoc
    result = await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff", "test-cycle",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    await asyncio.sleep(0.5)
    await sta.stop_capture()

    assert result.status == 0
    assert _pcap_has_auth(pcap_path, stas[0].mac), "Auth frame not found in pcap"
    assert _pcap_has_assoc(pcap_path, stas[0].mac), "Assoc frame not found in pcap"


@pytest.mark.scenario("sta_association")
async def test_sta_full_cycle_with_data_plane(ap_configured, sta, test_log_dir):
    """Full cycle: Assoc → DHCP Discover → DHCP Request → ARP → Ping."""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:07:22")
    pcap_path = test_log_dir / "air.pcap"

    await sta.start_capture(pcap_path)

    # Management plane
    result = await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff", "test-data",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    assert result.status == 0

    # Data plane: DHCP Discover
    dhcp_disc = build_dhcp_discover(stas[0].mac, "ff:ff:ff:ff:ff:ff")
    await sta.transport.send(dhcp_disc)
    await asyncio.sleep(0.5)

    # DHCP Request
    dhcp_req = build_dhcp_request(stas[0].mac, "ff:ff:ff:ff:ff:ff")
    await sta.transport.send(dhcp_req)
    await asyncio.sleep(0.5)

    # ARP Request
    arp_req = build_arp_request(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                                target_ip="192.168.1.1", sender_ip="192.168.1.100")
    await sta.transport.send(arp_req)
    await asyncio.sleep(0.5)

    # ICMP Echo (ping)
    ping = build_icmp_echo(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                           src_ip="192.168.1.100", dst_ip="192.168.1.1", seq=1)
    await sta.transport.send(ping)
    await asyncio.sleep(0.5)

    # Deauth to close
    from src.wlan.frames import build_deauth_frame
    deauth = build_deauth_frame(stas[0].mac, "ff:ff:ff:ff:ff:ff",
                                "ff:ff:ff:ff:ff:ff", reason=1)
    await sta.transport.send(deauth)

    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    assert len(pkts) >= 3, f"Expected at least 3 frames in pcap, got {len(pkts)}"
