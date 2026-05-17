"""Tests for SSHConnection."""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.connections.base import SSHResult
from src.connections.ssh import SSHConnection


class TestSSHResult:
    def test_dataclass_creation(self):
        result = SSHResult(stdout="out", stderr="err", exit_code=0)
        assert result.stdout == "out"
        assert result.stderr == "err"
        assert result.exit_code == 0

    def test_dataclass_defaults(self):
        result = SSHResult(stdout="", stderr="", exit_code=1)
        assert result.exit_code == 1


class TestSSHConnectionInit:
    def test_default_params(self):
        conn = SSHConnection(host="192.168.1.1")
        assert conn.host == "192.168.1.1"
        assert conn.port == 22
        assert conn.user == "root"
        assert conn.password is None
        assert conn.key_file is None
        assert conn._client is None

    def test_custom_params(self):
        conn = SSHConnection(
            host="10.0.0.1",
            port=2222,
            user="admin",
            password="secret",
            key_file="/home/user/id_rsa",
        )
        assert conn.host == "10.0.0.1"
        assert conn.port == 2222
        assert conn.user == "admin"
        assert conn.password == "secret"
        assert conn.key_file == "/home/user/id_rsa"

    def test_is_connected_false_by_default(self):
        conn = SSHConnection(host="192.168.1.1")
        assert not conn.is_connected

    def test_is_connected_true_after_setting_client(self):
        conn = SSHConnection(host="192.168.1.1")
        conn._client = MagicMock()
        assert conn.is_connected

    @pytest.mark.asyncio
    async def test_disconnect_sets_client_to_none(self):
        conn = SSHConnection(host="192.168.1.1")
        mock_client = MagicMock()
        conn._client = mock_client
        await conn.disconnect()
        mock_client.close.assert_called_once()
        assert conn._client is None


class TestSSHPushPullFile:
    @pytest.mark.asyncio
    async def test_push_file_uses_sftp_and_closes(self):
        mock_sftp = MagicMock()
        mock_client = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp

        loop_mock = MagicMock()
        loop_mock.run_in_executor = AsyncMock(
            side_effect=lambda executor, func: func(),
        )

        conn = SSHConnection(host="192.168.1.1")
        conn._client = mock_client

        with patch("src.connections.ssh.asyncio.get_event_loop", return_value=loop_mock):
            await conn.push_file(Path("/local/file"), "/remote/file")

        mock_client.open_sftp.assert_called_once()
        mock_sftp.put.assert_called_once_with("/local/file", "/remote/file")
        mock_sftp.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_pull_file_uses_sftp_and_closes(self):
        mock_sftp = MagicMock()
        mock_client = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp

        loop_mock = MagicMock()
        loop_mock.run_in_executor = AsyncMock(
            side_effect=lambda executor, func: func(),
        )

        conn = SSHConnection(host="192.168.1.1")
        conn._client = mock_client

        with patch("src.connections.ssh.asyncio.get_event_loop", return_value=loop_mock):
            await conn.pull_file("/remote/file", Path("/local/file"))

        mock_client.open_sftp.assert_called_once()
        mock_sftp.get.assert_called_once_with("/remote/file", "/local/file")
        mock_sftp.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_push_file_closes_sftp_on_failure(self):
        mock_sftp = MagicMock()
        mock_sftp.put.side_effect = OSError("disk full")
        mock_client = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp

        loop_mock = MagicMock()
        loop_mock.run_in_executor = AsyncMock(side_effect=OSError("disk full"))

        conn = SSHConnection(host="192.168.1.1")
        conn._client = mock_client

        with patch("src.connections.ssh.asyncio.get_event_loop", return_value=loop_mock):
            with pytest.raises(OSError, match="disk full"):
                await conn.push_file(Path("/local/file"), "/remote/file")

        mock_sftp.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_pull_file_closes_sftp_on_failure(self):
        mock_sftp = MagicMock()
        mock_client = MagicMock()
        mock_client.open_sftp.return_value = mock_sftp

        loop_mock = MagicMock()
        loop_mock.run_in_executor = AsyncMock(side_effect=OSError("not found"))

        conn = SSHConnection(host="192.168.1.1")
        conn._client = mock_client

        with patch("src.connections.ssh.asyncio.get_event_loop", return_value=loop_mock):
            with pytest.raises(OSError, match="not found"):
                await conn.pull_file("/remote/file", Path("/local/file"))

        mock_sftp.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_push_file_raises_if_not_connected(self):
        conn = SSHConnection(host="192.168.1.1")
        with pytest.raises(RuntimeError, match="Not connected"):
            await conn.push_file(Path("/local/file"), "/remote/file")

    @pytest.mark.asyncio
    async def test_pull_file_raises_if_not_connected(self):
        conn = SSHConnection(host="192.168.1.1")
        with pytest.raises(RuntimeError, match="Not connected"):
            await conn.pull_file("/remote/file", Path("/local/file"))
