"""Radio transport via Intel AX200 monitor mode + injection."""

import asyncio
from pathlib import Path
from scapy.all import sendp, AsyncSniffer, wrpcap, conf

from src.connections.ssh import SSHConnection
from src.transport.base import FrameTransport


class RadioTransport(FrameTransport):
    def __init__(self, interface: str, ssh: SSHConnection, channel: int = 6):
        self.interface = interface
        self.ssh = ssh
        self.channel = channel
        self._sniffer: AsyncSniffer | None = None
        self._pcap_path: str = ""

    async def setup(self) -> None:
        """Put interface into monitor mode and set channel."""
        cmds = [
            f"ip link set {self.interface} down",
            f"iw dev {self.interface} set type monitor",
            f"ip link set {self.interface} up",
            f"iw dev {self.interface} set channel {self.channel}",
        ]
        for cmd in cmds:
            result = await self.ssh.exec_sudo(cmd)
            if result.exit_code != 0:
                raise RuntimeError(
                    f"Failed to setup monitor mode: {cmd}\n{result.stderr}"
                )

    async def teardown(self) -> None:
        """Restore interface to managed mode."""
        await self.stop_capture()
        await self.ssh.exec_sudo(f"ip link set {self.interface} down")
        await self.ssh.exec_sudo(f"iw dev {self.interface} set type managed")
        await self.ssh.exec_sudo(f"ip link set {self.interface} up")

    async def send(self, frame: bytes) -> None:
        def _send():
            sendp(frame, iface=self.interface, verbose=False)
        await asyncio.get_event_loop().run_in_executor(None, _send)

    async def start_capture(self, pcap_path: str,
                            bpf_filter: str = "") -> None:
        self._pcap_path = pcap_path

        def _capture(pkt):
            wrpcap(pcap_path, pkt, append=True)

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=bpf_filter,
            prn=_capture,
        )
        self._sniffer.start()
        await asyncio.sleep(0.5)

    async def stop_capture(self) -> str:
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        return self._pcap_path
