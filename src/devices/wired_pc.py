"""Wired PC traffic generator — scapy-based 802.3 packet generation via SSH."""

import asyncio
from pathlib import Path

from src.connections.ssh import SSHConnection


class TrafficGenerator:
    """High-level traffic generation on the wired PC via SSH."""

    def __init__(self, ssh: SSHConnection, interface: str = "eth1"):
        self._ssh = ssh
        self.interface = interface
        self._capture_pid: str | None = None
        self._pcap_path: str = ""

    async def _send_script(self, script: str) -> None:
        """Push a scapy script to remote and execute."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False,
                                         mode="w") as f:
            f.write(script)
            script_path = f.name
        remote_path = "/tmp/_traffic_gen.py"
        await self._ssh.push_file(Path(script_path), remote_path)
        result = await self._ssh.exec_sudo(f"python3 {remote_path}")
        Path(script_path).unlink()
        if result.exit_code != 0:
            raise RuntimeError(f"Traffic script failed: {result.stderr}")

    def _make_send_script(self, packet_code: str, count: int) -> str:
        return f"""
from scapy.all import *
import sys
pkt = {packet_code}
if isinstance(pkt, list):
    for p in pkt:
        sendp(p, iface="{self.interface}", verbose=False)
else:
    for _ in range({count}):
        sendp(pkt, iface="{self.interface}", verbose=False)
"""

    async def send_arp(self, op: int, src_ip: str, dst_ip: str,
                       src_mac: str = "00:11:22:33:44:01",
                       dst_mac: str = "ff:ff:ff:ff:ff:ff",
                       count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether(src='{src_mac}', dst='{dst_mac}') / "
            f"ARP(op={op}, hwsrc='{src_mac}', psrc='{src_ip}', "
            f"hwdst='00:00:00:00:00:00', pdst='{dst_ip}')",
            count,
        )
        await self._send_script(script)

    async def send_icmp(self, src_ip: str, dst_ip: str,
                        icmp_type: int = 8, count: int = 1,
                        size: int = 64) -> None:
        payload_size = max(0, size - 14 - 20 - 8)
        script = self._make_send_script(
            f"Ether() / IP(src='{src_ip}', dst='{dst_ip}') / "
            f"ICMP(type={icmp_type}) / Raw(b'\\x00' * {payload_size})",
            count,
        )
        await self._send_script(script)

    async def send_tcp(self, src_ip: str, dst_ip: str,
                       sport: int, dport: int,
                       src_mac: str = "00:11:22:33:44:01",
                       dst_mac: str = "00:11:22:33:44:02",
                       flags: str = "S", count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether(src='{src_mac}', dst='{dst_mac}') / "
            f"IP(src='{src_ip}', dst='{dst_ip}') / "
            f"TCP(sport={sport}, dport={dport}, flags='{flags}')",
            count,
        )
        await self._send_script(script)

    async def send_udp(self, src_ip: str, dst_ip: str,
                       sport: int, dport: int,
                       payload: bytes = b"",
                       count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether() / IP(src='{src_ip}', dst='{dst_ip}') / "
            f"UDP(sport={sport}, dport={dport}) / Raw({payload!r})",
            count,
        )
        await self._send_script(script)

    async def send_broadcast(self, src_ip: str,
                             payload: bytes = b"test",
                             count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether(dst='ff:ff:ff:ff:ff:ff') / "
            f"IP(src='{src_ip}', dst='255.255.255.255') / Raw({payload!r})",
            count,
        )
        await self._send_script(script)

    async def send_multicast(self, group: str,
                             payload: bytes = b"test",
                             count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether() / IP(src='192.168.1.100', dst='{group}') / Raw({payload!r})",
            count,
        )
        await self._send_script(script)

    async def send_jumbo(self, src_ip: str, dst_ip: str,
                         size: int = 9000) -> None:
        payload_size = max(0, size - 14 - 20 - 8)
        script = self._make_send_script(
            f"Ether() / IP(src='{src_ip}', dst='{dst_ip}') / "
            f"ICMP() / Raw(b'\\x00' * {payload_size})",
            1,
        )
        await self._send_script(script)

    async def send_fragmented(self, payload: bytes,
                              frag_size: int = 1480) -> None:
        script = f"""
from scapy.all import *
pkt = Ether() / IP(src='192.168.1.100', dst='192.168.1.1') / ICMP() / Raw({payload!r})
frags = fragment(pkt, fragsize={frag_size})
for f in frags:
    sendp(f, iface="{self.interface}", verbose=False)
"""
        await self._send_script(script)

    async def start_capture(self, pcap_path: str,
                            bpf_filter: str = "") -> None:
        self._pcap_path = pcap_path
        filter_arg = f"'{bpf_filter}'" if bpf_filter else ""
        result = await self._ssh.exec_sudo(
            f"tcpdump -i {self.interface} {filter_arg} -w {pcap_path} & "
            f"echo $!"
        )
        self._capture_pid = result.stdout.strip()

    async def stop_capture(self) -> str:
        if self._capture_pid:
            await self._ssh.exec_sudo(f"kill {self._capture_pid}")
            self._capture_pid = None
        return self._pcap_path
