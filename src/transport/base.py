"""Frame transport abstraction for 802.11 frame send/receive."""

from abc import ABC, abstractmethod
from pathlib import Path


class TransportError(Exception):
    """Base exception for transport layer failures."""


class FrameTransport(ABC):
    @abstractmethod
    async def send(self, frame: bytes) -> None: ...

    @abstractmethod
    async def start_capture(self, pcap_path: Path,
                            bpf_filter: str = "") -> None: ...

    @abstractmethod
    async def stop_capture(self) -> str: ...
