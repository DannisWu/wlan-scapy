"""PCAP capture management."""

import asyncio
import os
from pathlib import Path
from scapy.all import sniff, wrpcap, rdpcap, AsyncSniffer


class PCAPManager:
    """Manage pcap capture lifecycle per device."""

    def __init__(self, interface: str = "", output_dir: Path = Path(".")):
        self.interface = interface
        self.output_dir = output_dir
        self._sniffer: AsyncSniffer | None = None
        self._current_path: Path | None = None

    async def start(self, label: str, bpf_filter: str = "") -> str:
        self._current_path = self.output_dir / f"{label}_{_timestamp()}.pcap"
        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=bpf_filter,
            prn=lambda pkt: wrpcap(str(self._current_path), pkt, append=True),
        )
        self._sniffer.start()
        await asyncio.sleep(0.5)  # let sniffer start
        return str(self._current_path)

    async def stop(self) -> str:
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        return str(self._current_path) if self._current_path else ""

    @staticmethod
    def read(pcap_path: str | Path):
        return rdpcap(str(pcap_path))

    @staticmethod
    def check_packets(pcap_path: str | Path, condition) -> list:
        """Return packets matching condition callable."""
        packets = rdpcap(str(pcap_path))
        return [p for p in packets if condition(p)]

    @staticmethod
    def verify_sequence(pcap_path: str | Path,
                        conditions: list) -> bool:
        """Verify a sequence of conditions appears in order."""
        packets = rdpcap(str(pcap_path))
        ci = 0
        for pkt in packets:
            if ci < len(conditions) and conditions[ci](pkt):
                ci += 1
        return ci == len(conditions)


def _timestamp() -> str:
    import time
    return time.strftime("%Y%m%d_%H%M%S")
