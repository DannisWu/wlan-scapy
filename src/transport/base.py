"""Frame transport abstraction for 802.11 frame send/receive."""

from abc import ABC, abstractmethod


class FrameTransport(ABC):
    @abstractmethod
    async def send(self, frame: bytes) -> None: ...

    @abstractmethod
    async def start_capture(self, pcap_path: str,
                            bpf_filter: str = "") -> None: ...

    @abstractmethod
    async def stop_capture(self) -> str: ...
