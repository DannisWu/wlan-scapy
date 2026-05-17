"""Telnet connection to DUT AP CLI."""

import asyncio
import re

import telnetlib3

from src.connections.base import TelnetResult


class TelnetConnection:
    def __init__(self, host: str, port: int = 23,
                 prompt_suffixes: tuple[str, ...] = ("# ", "> ", "? ", "$ ", ":")):
        self.host = host
        self.port = port
        self.prompt_suffixes = prompt_suffixes
        self._reader = None
        self._writer = None

    async def connect(self) -> None:
        self._reader, self._writer = await telnetlib3.open_connection(
            self.host, self.port, timeout=10,
        )

    async def disconnect(self) -> None:
        if self._writer:
            self._writer.close()
            self._reader = None
            self._writer = None

    async def send_cmd(self, cmd: str, timeout: float = 30) -> TelnetResult:
        if not self._writer:
            raise RuntimeError("Not connected")
        self._writer.write(cmd + "\r\n")
        output = await self._read_until_prompt(timeout)
        return TelnetResult(output=output)

    async def wait_for(self, pattern: str, timeout: float = 30) -> str:
        deadline = asyncio.get_running_loop().time() + timeout
        collected = ""
        while asyncio.get_running_loop().time() < deadline:
            try:
                data = await asyncio.wait_for(
                    self._reader.read(4096), timeout=1.0,
                )
                if data:
                    collected += data
                    if re.search(pattern, collected):
                        return collected
            except asyncio.TimeoutError:
                continue
        raise TimeoutError(f"Pattern '{pattern}' not found within {timeout}s")

    async def send_cmd_expect(self, cmd: str, expected: str,
                              timeout: float = 30) -> bool:
        if not self._writer:
            raise RuntimeError("Not connected")
        self._writer.write(cmd + "\r\n")
        try:
            await self.wait_for(expected, timeout)
            return True
        except TimeoutError:
            return False

    async def _read_until_prompt(self, timeout: float) -> str:
        """Read until CLI prompt is detected."""
        deadline = asyncio.get_running_loop().time() + timeout
        collected = ""
        while asyncio.get_running_loop().time() < deadline:
            try:
                data = await asyncio.wait_for(
                    self._reader.read(4096), timeout=1.0,
                )
                if data:
                    collected += data
                    if collected.rstrip().endswith(self.prompt_suffixes):
                        return collected
            except asyncio.TimeoutError:
                if collected:
                    return collected
                continue
        return collected

    @property
    def is_connected(self) -> bool:
        return self._writer is not None
