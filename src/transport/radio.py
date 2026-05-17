"""Radio transport via Intel AX200 monitor mode + injection."""

import base64
import logging
import tempfile
from pathlib import Path

from src.connections.ssh import SSHConnection
from src.transport.base import FrameTransport, TransportError

logger = logging.getLogger(__name__)


class RadioTransport(FrameTransport):
    def __init__(self, interface: str, ssh: SSHConnection, channel: int = 6):
        self.interface = interface
        self.ssh = ssh
        self.channel = channel
        self._capture_pid: str | None = None
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
                raise TransportError(
                    f"Failed to setup monitor mode: {cmd}\n{result.stderr}"
                )

    async def teardown(self) -> None:
        """Restore interface to managed mode."""
        await self.stop_capture()
        for cmd in [
            f"ip link set {self.interface} down",
            f"iw dev {self.interface} set type managed",
            f"ip link set {self.interface} up",
        ]:
            result = await self.ssh.exec_sudo(cmd)
            if result.exit_code != 0:
                logger.warning(
                    "teardown command failed (exit=%d): %s\n%s",
                    result.exit_code, cmd, result.stderr,
                )

    async def send(self, frame: bytes) -> None:
        """Send frame via scapy on remote STA."""
        frame_b64 = base64.b64encode(frame).decode("ascii")
        script = (
            "from scapy.all import sendp\n"
            "import base64\n"
            f"frame = base64.b64decode({frame_b64!r})\n"
            f"sendp(frame, iface=\"{self.interface}\", verbose=False)\n"
        )
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(script)
            script_path = f.name
        remote = "/tmp/_radio_send.py"
        try:
            await self.ssh.push_file(Path(script_path), remote)
            result = await self.ssh.exec_sudo(f"python3 {remote}")
            if result.exit_code != 0:
                raise TransportError(f"Frame send failed: {result.stderr}")
        finally:
            Path(script_path).unlink(missing_ok=True)

    async def start_capture(self, pcap_path: Path,
                            bpf_filter: str = "") -> None:
        self._pcap_path = str(pcap_path)
        filter_arg = f"'{bpf_filter}'" if bpf_filter else ""
        result = await self.ssh.exec_sudo(
            f"tcpdump -i {self.interface} {filter_arg} -w {self._pcap_path} -U "
            f"& echo $!"
        )
        if result.exit_code != 0:
            raise TransportError(
                f"Failed to start capture: {result.stderr}"
            )
        self._capture_pid = result.stdout.strip()

    async def stop_capture(self) -> str:
        if self._capture_pid:
            await self.ssh.exec_sudo(f"kill {self._capture_pid}")
            self._capture_pid = None
        # Pull pcap from remote
        local = Path("/tmp/_radio_capture.pcap")
        await self.ssh.pull_file(self._pcap_path, local)
        return str(local)
