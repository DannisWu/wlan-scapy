"""WLAN STA injector — multi-STA 802.11 frame injection."""

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from src.connections.ssh import SSHConnection
from src.transport.base import FrameTransport
from src.wlan.frames import (
    build_auth_frame, build_assoc_req_frame, build_deauth_frame,
)


class StaState(Enum):
    DISCONNECTED = "disconnected"
    AUTH = "auth"
    ASSOCIATED = "associated"
    FOURWAY = "4way"


@dataclass
class HTCapabilities:
    raw: bytes = b"\x00" * 26


@dataclass
class VHTCapabilities:
    raw: bytes = b"\x00" * 12


@dataclass
class HECapabilities:
    raw: bytes = b"\x00" * 32


@dataclass
class RSNAuthParams:
    auth: str = "WPA2"
    psk: str = ""
    encryption: str = "aes"


@dataclass
class SecurityParams:
    auth: str = "WPA2"
    psk: str = ""
    encryption: str = "aes"


@dataclass
class AssocResult:
    status: int = 0
    aid: int = 0
    bssid: str = ""


@dataclass
class StaInstance:
    mac: str
    capabilities: int = 0x0431
    supported_rates: list[int] = field(default_factory=lambda: [
        0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
    ])
    ht_cap: HTCapabilities | None = None
    vht_cap: VHTCapabilities | None = None
    he_cap: HECapabilities | None = None
    state: StaState = StaState.DISCONNECTED
    rsn: RSNAuthParams | None = None


class StaInjector:
    """Manage multiple virtual STAs via frame injection."""

    def __init__(self, transport: FrameTransport, ssh: SSHConnection):
        self.transport = transport
        self.ssh = ssh
        self.stas: list[StaInstance] = []

    async def create_stas(self, count: int,
                          base_mac: str = "00:11:22:33:00:00") -> list[StaInstance]:
        parts = base_mac.split(":")
        base = int("".join(parts), 16)
        self.stas = []
        for i in range(count):
            mac_int = base + i
            mac = ":".join(f"{(mac_int >> (40 - 8 * j)) & 0xff:02x}"
                           for j in range(6))
            self.stas.append(StaInstance(mac=mac))
        return self.stas

    async def destroy_stas(self) -> None:
        for sta in self.stas:
            if sta.state != StaState.DISCONNECTED:
                await self.send_frame(
                    sta,
                    build_deauth_frame(sta.mac, "ff:ff:ff:ff:ff:ff",
                                       "ff:ff:ff:ff:ff:ff", reason=3),
                )
        self.stas.clear()

    async def associate(self, sta: StaInstance, bssid: str,
                        ssid: str, security: SecurityParams) -> AssocResult:
        seq = 0
        # Auth seq 1
        await self.send_frame(
            sta,
            build_auth_frame(sta.mac, bssid, bssid, seq_num=seq, seq=1),
        )
        sta.state = StaState.AUTH

        # Assoc request
        seq += 1
        await self.send_frame(
            sta,
            build_assoc_req_frame(sta.mac, bssid, bssid, ssid,
                                  sta.capabilities, sta.supported_rates,
                                  seq_num=seq),
        )
        sta.state = StaState.ASSOCIATED

        # In a real test, the AP responds with AssocResp.
        # The test layer verifies the response from the pcap.
        return AssocResult(status=0, bssid=bssid)

    async def send_auth(self, sta: StaInstance, bssid: str,
                        algo: int = 0, seq: int = 1,
                        status: int = 0) -> None:
        frame = build_auth_frame(sta.mac, bssid, bssid,
                                 algo=algo, seq=seq, status=status)
        await self.transport.send(frame)

    async def send_assoc(self, sta: StaInstance, bssid: str,
                         ssid: str) -> None:
        frame = build_assoc_req_frame(sta.mac, bssid, bssid, ssid,
                                      sta.capabilities, sta.supported_rates)
        await self.transport.send(frame)

    async def send_frame(self, sta: StaInstance, frame: bytes) -> None:
        await self.transport.send(frame)

    async def send_sequence(self, sta: StaInstance, sequence) -> None:
        for step in sequence.steps:
            await self.transport.send(step.frame)
            if step.delay > 0:
                await asyncio.sleep(step.delay)

    async def associate_all(self, bssid: str,
                            ssid: str) -> list[AssocResult]:
        results = []
        for sta in self.stas:
            result = await self.associate(
                sta, bssid, ssid,
                SecurityParams(auth="WPA2", psk="test1234"),
            )
            results.append(result)
        return results

    async def start_capture(self, pcap_path: Path,
                            bpf_filter: str = "") -> None:
        await self.transport.start_capture(pcap_path, bpf_filter)

    async def stop_capture(self) -> str:
        return await self.transport.stop_capture()
