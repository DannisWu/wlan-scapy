"""DUT AP controller — Telnet CLI + serial monitoring."""

from dataclasses import dataclass
from pathlib import Path

from src.connections.telnet import TelnetConnection
from src.connections.serial import SerialConnection
from src.cli.parser import CLIParser


@dataclass
class StaInfo:
    mac: str
    aid: int = 0
    rssi: int = 0
    state: str = ""


class APController:
    """High-level DUT AP operations via Telnet CLI with serial monitoring."""

    DEFAULT_DMESG_ERRORS = [
        "oops", "panic", "BUG:", "Call Trace", "WARNING:", "ERROR:",
        "Firmware error", "iwlw.*fail", "iwlw.*error",
    ]

    def __init__(self, telnet: TelnetConnection,
                 serial: SerialConnection | None = None):
        self._telnet = telnet
        self._serial = serial
        self._parser = CLIParser()

    # --- Radio config ---
    async def set_radio(self, channel: int, mode: str,
                        bandwidth: int = 20) -> None:
        cmds = [
            f"radio channel {channel}",
            f"radio mode {mode}",
            f"radio bandwidth {bandwidth}",
        ]
        for cmd in cmds:
            await self._telnet.send_cmd(cmd)

    async def set_ssid(self, ssid: str, index: int = 0) -> None:
        await self._telnet.send_cmd(f"ssid {ssid} index {index}")

    async def set_security(self, auth: str, encryption: str = "aes",
                           psk: str | None = None) -> None:
        await self._telnet.send_cmd(f"security auth {auth} enc {encryption}")
        if psk:
            await self._telnet.send_cmd(f"security psk {psk}")

    # --- Status queries ---
    async def get_sta_list(self) -> list[StaInfo]:
        result = await self._telnet.send_cmd("show sta")
        entries = self._parser.parse_sta_list(result.output)
        return [StaInfo(
            mac=e.get("mac", ""),
            aid=int(e.get("aid", 0)),
            rssi=int(e.get("rssi", 0)),
            state=e.get("state", ""),
        ) for e in entries]

    async def get_stats(self) -> dict:
        result = await self._telnet.send_cmd("show stats")
        return self._parser.parse_stats(result.output, "stats")

    # --- dmesg ---
    async def get_dmesg(self) -> str:
        result = await self._telnet.send_cmd("dmesg")
        return result.output

    async def clear_dmesg(self) -> None:
        await self._telnet.send_cmd("dmesg -c")

    async def check_dmesg(self, before: str, after: str,
                          patterns: list[str] | None = None) -> list[str]:
        import re
        pats = patterns or self.DEFAULT_DMESG_ERRORS
        before_lines = set(before.split("\n"))
        after_lines = set(after.split("\n"))
        new_lines = after_lines - before_lines
        errors = []
        for line in new_lines:
            for p in pats:
                if re.search(p, line, re.IGNORECASE):
                    errors.append(line.strip())
                    break
        return errors

    # --- Serial monitoring ---
    async def start_monitoring(self, log_dir: Path) -> None:
        if self._serial:
            log_file = log_dir / "serial.log"
            await self._serial.start_monitor(log_file)

    async def stop_monitoring(self) -> tuple[str, list[str]]:
        if self._serial:
            log_path = await self._serial.stop_monitor()
            errors = await self._serial.check_errors()
            return log_path, errors
        return "", []

    # --- Control ---
    async def reboot(self) -> None:
        await self._telnet.send_cmd_expect("reboot", "confirm")
        await self._telnet.send_cmd("y")

    async def factory_reset(self) -> None:
        await self._telnet.send_cmd("factory-reset")
        if await self._telnet.send_cmd_expect("", "confirm"):
            await self._telnet.send_cmd("y")

    async def clear_logs(self) -> None:
        await self._telnet.send_cmd("clear-log")
