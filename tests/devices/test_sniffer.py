"""Unit tests for SnifferDevice."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.devices.sniffer import SnifferDevice
from src.connections.base import SSHResult


class TestSnifferDevice:
    @pytest.fixture
    def mock_ssh(self):
        ssh = MagicMock()
        ssh.exec_sudo = AsyncMock(return_value=SSHResult("", "", 0))
        return ssh

    @pytest.fixture
    def sniffer(self, mock_ssh):
        return SnifferDevice(mock_ssh, "wlan1mon")

    async def test_setup_success(self, sniffer, mock_ssh):
        await sniffer.setup(channel=36)
        calls = [c[0][0] for c in mock_ssh.exec_sudo.call_args_list]
        assert any("set type monitor" in c for c in calls)
        assert any("set channel 36" in c for c in calls)

    async def test_setup_failure_raises(self, sniffer, mock_ssh):
        mock_ssh.exec_sudo.return_value = SSHResult("", "Busy", 1)
        with pytest.raises(RuntimeError, match="Sniffer setup failed"):
            await sniffer.setup(channel=6)

    async def test_start_capture_gets_pid(self, sniffer, mock_ssh):
        mock_ssh.exec_sudo.return_value = SSHResult("12345\n", "", 0)
        await sniffer.start_capture(Path("/tmp/test.pcap"))
        assert sniffer._capture_pid == "12345"
        assert sniffer._pcap_remote != ""

    async def test_stop_capture_kills_pid(self, sniffer, mock_ssh):
        sniffer._capture_pid = "12345"
        sniffer._pcap_remote = "/tmp/sniffer_test.pcap"
        mock_ssh.pull_file = AsyncMock()
        await sniffer.stop_capture()
        assert sniffer._capture_pid is None
        mock_ssh.pull_file.assert_called_once()

    async def test_teardown_stops_capture_and_restores(self, sniffer, mock_ssh):
        sniffer._capture_pid = "12345"
        sniffer._pcap_remote = "/tmp/sniffer_test.pcap"
        mock_ssh.pull_file = AsyncMock()
        await sniffer.teardown()
        calls = [c[0][0] for c in mock_ssh.exec_sudo.call_args_list]
        assert any("set type managed" in c for c in calls)
