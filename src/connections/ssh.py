"""SSH connection to Wired PC / WLAN STA."""

import asyncio
from pathlib import Path

import paramiko

from src.connections.base import SSHResult


class SSHConnection:
    def __init__(self, host: str, port: int = 22,
                 user: str = "root", password: str | None = None,
                 key_file: str | None = None):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.key_file = key_file
        self._client: paramiko.SSHClient | None = None

    async def connect(self) -> None:
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.connect(
                self.host, self.port, self.user,
                password=self.password,
                key_filename=self.key_file,
                timeout=10,
            ),
        )

    async def disconnect(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    async def exec(self, cmd: str, timeout: float = 30) -> SSHResult:
        if not self._client:
            raise RuntimeError("Not connected")
        stdin, stdout, stderr = await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._client.exec_command(cmd, timeout=timeout),
        )
        out = await asyncio.get_event_loop().run_in_executor(
            None, stdout.read,
        )
        err = await asyncio.get_event_loop().run_in_executor(
            None, stderr.read,
        )
        exit_code = stdout.channel.recv_exit_status()
        return SSHResult(
            stdout=out.decode("utf-8", errors="replace"),
            stderr=err.decode("utf-8", errors="replace"),
            exit_code=exit_code,
        )

    async def exec_sudo(self, cmd: str, timeout: float = 30) -> SSHResult:
        return await self.exec(f"sudo {cmd}", timeout=timeout)

    async def push_file(self, local: Path, remote: str) -> None:
        if not self._client:
            raise RuntimeError("Not connected")
        sftp = self._client.open_sftp()
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: sftp.put(str(local), remote),
            )
        finally:
            sftp.close()

    async def pull_file(self, remote: str, local: Path) -> None:
        if not self._client:
            raise RuntimeError("Not connected")
        sftp = self._client.open_sftp()
        try:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: sftp.get(remote, str(local)),
            )
        finally:
            sftp.close()

    @property
    def is_connected(self) -> bool:
        return self._client is not None
