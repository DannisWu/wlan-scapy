"""Wired PC traffic generator — scapy-based 802.3 packet generation via SSH."""

import asyncio
import functools
import re
import shlex
from pathlib import Path

from src.connections.ssh import SSHConnection

_VALID_IP = re.compile(r"^[0-9.]{7,15}$")
_VALID_MAC = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_VALID_FLAGS = re.compile(r"^[SRAFPU]+$")
_VALID_GROUP = re.compile(r"^[0-9.]{7,15}$")


def _validate_param(value: str, pattern: re.Pattern, name: str) -> None:
    if not pattern.match(value):
        raise ValueError(f"Invalid {name}: {value!r}")


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
        loop = asyncio.get_running_loop()
        fp = await loop.run_in_executor(
            None,
            functools.partial(
                tempfile.NamedTemporaryFile,
                mode="w",
                suffix=".py",
                delete=False,
            ),
        )
        script_path = fp.name
        try:
            fp.write(script)
            fp.close()
            remote_path = "/tmp/_traffic_gen.py"
            await self._ssh.push_file(Path(script_path), remote_path)
            result = await self._ssh.exec_sudo(f"python3 {remote_path}")
            if result.exit_code != 0:
                raise RuntimeError(f"Traffic script failed: {result.stderr}")
        finally:
            await loop.run_in_executor(None, Path(script_path).unlink)

    def _make_send_script(self, packet_code: str, count: int) -> str:
        if "\n" in packet_code or "\r" in packet_code:
            raise ValueError("Packet code contains control characters")
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
        _validate_param(src_ip, _VALID_IP, "src_ip")
        _validate_param(dst_ip, _VALID_IP, "dst_ip")
        _validate_param(src_mac, _VALID_MAC, "src_mac")
        _validate_param(dst_mac, _VALID_MAC, "dst_mac")
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
        _validate_param(src_ip, _VALID_IP, "src_ip")
        _validate_param(dst_ip, _VALID_IP, "dst_ip")
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
        _validate_param(src_ip, _VALID_IP, "src_ip")
        _validate_param(dst_ip, _VALID_IP, "dst_ip")
        _validate_param(src_mac, _VALID_MAC, "src_mac")
        _validate_param(dst_mac, _VALID_MAC, "dst_mac")
        _validate_param(flags, _VALID_FLAGS, "flags")
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
        _validate_param(src_ip, _VALID_IP, "src_ip")
        _validate_param(dst_ip, _VALID_IP, "dst_ip")
        script = self._make_send_script(
            f"Ether() / IP(src='{src_ip}', dst='{dst_ip}') / "
            f"UDP(sport={sport}, dport={dport}) / Raw({payload!r})",
            count,
        )
        await self._send_script(script)

    async def send_broadcast(self, src_ip: str,
                             payload: bytes = b"test",
                             count: int = 1) -> None:
        _validate_param(src_ip, _VALID_IP, "src_ip")
        script = self._make_send_script(
            f"Ether(dst='ff:ff:ff:ff:ff:ff') / "
            f"IP(src='{src_ip}', dst='255.255.255.255') / Raw({payload!r})",
            count,
        )
        await self._send_script(script)

    async def send_multicast(self, group: str,
                             payload: bytes = b"test",
                             count: int = 1) -> None:
        _validate_param(group, _VALID_GROUP, "group")
        script = self._make_send_script(
            f"Ether() / IP(src='192.168.1.100', dst='{group}') / Raw({payload!r})",
            count,
        )
        await self._send_script(script)

    async def send_jumbo(self, src_ip: str, dst_ip: str,
                         size: int = 9000) -> None:
        _validate_param(src_ip, _VALID_IP, "src_ip")
        _validate_param(dst_ip, _VALID_IP, "dst_ip")
        payload_size = max(0, size - 14 - 20 - 8)
        script = self._make_send_script(
            f"Ether() / IP(src='{src_ip}', dst='{dst_ip}') / "
            f"ICMP() / Raw(b'\\x00' * {payload_size})",
            1,
        )
        await self._send_script(script)

    async def send_fragmented(self, payload: bytes,
                              src_ip: str = "192.168.1.100",
                              dst_ip: str = "192.168.1.1",
                              frag_size: int = 1480) -> None:
        _validate_param(src_ip, _VALID_IP, "src_ip")
        _validate_param(dst_ip, _VALID_IP, "dst_ip")
        script = f"""
from scapy.all import *
pkt = Ether() / IP(src='{src_ip}', dst='{dst_ip}') / ICMP() / Raw({payload!r})
frags = fragment(pkt, fragsize={frag_size})
for f in frags:
    sendp(f, iface="{self.interface}", verbose=False)
"""
        await self._send_script(script)

    async def start_capture(self, pcap_path: str,
                            bpf_filter: str = "") -> None:
        self._pcap_path = pcap_path
        filter_part = shlex.quote(bpf_filter) if bpf_filter else ""
        result = await self._ssh.exec_sudo(
            f"tcpdump -i {self.interface} -w {shlex.quote(pcap_path)} "
            f"{filter_part} -U & echo $!"
        )
        self._capture_pid = result.stdout.strip()

    async def stop_capture(self) -> str:
        if self._capture_pid:
            await self._ssh.exec_sudo(f"kill {self._capture_pid}")
            self._capture_pid = None
        return self._pcap_path
