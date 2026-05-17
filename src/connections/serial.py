"""Serial connection to DUT AP — passive monitoring for oops/panic."""

import asyncio
from pathlib import Path

from src.connections.base import SerialMode


class SerialConnection:
    DEFAULT_ERROR_PATTERNS = [
        "oops", "panic", "BUG:", "Call Trace", "WARNING:",
        "ERROR:", "Firmware error", "iwlw.*fail", "iwlw.*error",
        "Kernel panic", "Unable to handle",
    ]

    def __init__(self):
        self._reader = None
        self._active = False
        self._buffer: list[str] = []
        self._mode: SerialMode | None = None
        self._drain_task: asyncio.Task | None = None
        self._log_file: Path | None = None

    async def open(self, mode: SerialMode, **kwargs) -> None:
        self._mode = mode
        if mode == SerialMode.LOCAL:
            import serial as pyserial
            port = kwargs["port"]
            baudrate = kwargs.get("baudrate", 115200)
            self._reader = pyserial.Serial(port, baudrate, timeout=0.1)
        elif mode == SerialMode.COMHUB:
            import telnetlib3
            host = kwargs["host"]
            port = kwargs.get("port", 23)
            reader, writer = await telnetlib3.open_connection(host, port, timeout=10)
            self._reader = _TelnetReader(reader)

    async def close(self) -> None:
        await self.stop_monitor()
        if self._mode == SerialMode.LOCAL and self._reader:
            self._reader.close()
        self._reader = None

    async def start_monitor(self, log_file: Path) -> None:
        self._active = True
        self._buffer.clear()
        self._log_file = log_file
        self._drain_task = asyncio.create_task(self._drain_to_file())

    async def stop_monitor(self) -> str:
        self._active = False
        if self._drain_task:
            await self._drain_task
            self._drain_task = None
        return str(self._log_file) if self._log_file else ""

    async def _drain_to_file(self) -> None:
        with open(self._log_file, "a") as f:
            while self._active:
                try:
                    line = await self._read_line()
                    if line:
                        f.write(line)
                        f.flush()
                        self._buffer.append(line)
                except Exception:
                    await asyncio.sleep(0.1)

    async def _read_line(self) -> str | None:
        loop = asyncio.get_event_loop()
        if self._mode == SerialMode.LOCAL:
            if self._reader.in_waiting:
                raw = await loop.run_in_executor(None, self._reader.readline)
                return raw.decode("utf-8", errors="replace")
        elif self._mode == SerialMode.COMHUB:
            try:
                return await asyncio.wait_for(self._reader.read(), timeout=0.1)
            except asyncio.TimeoutError:
                pass
        return None

    async def check_errors(self, patterns: list[str] | None = None) -> list[str]:
        import re
        pats = patterns or self.DEFAULT_ERROR_PATTERNS
        errors = []
        for line in self._buffer:
            for p in pats:
                if re.search(p, line, re.IGNORECASE):
                    errors.append(line.strip())
                    break
        return errors


class _TelnetReader:
    """Wrap telnetlib3 reader to provide read_line interface."""
    def __init__(self, reader):
        self._reader = reader

    async def read(self) -> str:
        data = await self._reader.read(4096)
        return data if data else ""
