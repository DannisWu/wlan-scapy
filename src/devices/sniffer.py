"""WLAN Sniffer — passive 802.11 air capture via remote tcpdump."""

import time
from pathlib import Path

from src.connections.ssh import SSHConnection


class SnifferDevice:
    """Independent 802.11 air capture — passively monitors, never injects."""

    def __init__(self, ssh: SSHConnection, interface: str):
        self._ssh = ssh
        self.interface = interface
        self._capture_pid: str | None = None
        self._pcap_remote: str = ""

    async def setup(self, channel: int) -> None:
        """Put interface into monitor mode and set channel."""
        cmds = [
            f"ip link set {self.interface} down",
            f"iw dev {self.interface} set type monitor",
            f"ip link set {self.interface} up",
            f"iw dev {self.interface} set channel {channel}",
        ]
        for cmd in cmds:
            result = await self._ssh.exec_sudo(cmd)
            if result.exit_code != 0:
                raise RuntimeError(
                    f"Sniffer setup failed: {cmd}\n{result.stderr}"
                )

    async def teardown(self) -> None:
        """Stop capture and restore interface to managed mode."""
        await self.stop_capture()
        for cmd in [
            f"ip link set {self.interface} down",
            f"iw dev {self.interface} set type managed",
            f"ip link set {self.interface} up",
        ]:
            await self._ssh.exec_sudo(cmd)

    async def start_capture(self, pcap_path: Path,
                            bpf_filter: str = "") -> None:
        """Start remote tcpdump in background."""
        self._pcap_remote = f"/tmp/sniffer_{_timestamp()}.pcap"
        filter_arg = f"'{bpf_filter}'" if bpf_filter else ""
        result = await self._ssh.exec_sudo(
            f"tcpdump -i {self.interface} {filter_arg} "
            f"-w {self._pcap_remote} -U & echo $!"
        )
        if result.exit_code != 0:
            raise RuntimeError(
                f"Sniffer capture start failed: {result.stderr}"
            )
        self._capture_pid = result.stdout.strip()

    async def stop_capture(self) -> Path:
        """Stop tcpdump and pull pcap to local."""
        if self._capture_pid:
            await self._ssh.exec_sudo(f"kill {self._capture_pid}")
            self._capture_pid = None
        local = Path(f"/tmp/_sniffer_{_timestamp()}.pcap")
        await self._ssh.pull_file(self._pcap_remote, local)
        return local


def _timestamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")
