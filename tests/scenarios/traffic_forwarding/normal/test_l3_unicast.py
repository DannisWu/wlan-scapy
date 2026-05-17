"""L3 unicast traffic forwarding tests."""

import asyncio

import pytest


@pytest.mark.scenario("traffic_forwarding")
async def test_arp_forwarding(wired_pc, test_log_dir):
    pcap_path = str(test_log_dir / "wired.pcap")
    await wired_pc.start_capture(pcap_path)
    await wired_pc.send_arp(1, "192.168.1.100", "192.168.1.1", count=3)
    await asyncio.sleep(2)
    await wired_pc.stop_capture()

    from scapy.all import rdpcap
    pkts = rdpcap(pcap_path)
    arp_count = sum(1 for p in pkts if p.haslayer("ARP"))
    assert arp_count >= 3, f"Expected >= 3 ARP packets, got {arp_count}"


@pytest.mark.scenario("traffic_forwarding")
async def test_icmp_forwarding(wired_pc, test_log_dir):
    pcap_path = str(test_log_dir / "wired.pcap")
    await wired_pc.start_capture(pcap_path)
    await wired_pc.send_icmp("192.168.1.100", "192.168.1.1", count=3)
    await asyncio.sleep(2)
    await wired_pc.stop_capture()

    from scapy.all import rdpcap
    pkts = rdpcap(pcap_path)
    icmp_count = sum(1 for p in pkts if p.haslayer("ICMP"))
    assert icmp_count >= 3, f"Expected >= 3 ICMP packets, got {icmp_count}"
