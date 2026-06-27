"""WLAN test CLI runner — standalone frame injection.

Provides the WifiMgmtSender base class pattern from RUN/scapy,
rebuilt on top of wlan-scapy's modular frame builders.

Usage::

    python3 -m src.cli.run --help
    sudo python3 -m src.cli.run probe --iface wlan0mon --sta-count 10
"""

import argparse
import random
import subprocess
import sys
import threading
import time
from typing import List, Optional

from scapy.all import Dot11, conf, sendp

from src.wlan.frames import (  # convenience wrappers
    build_probe_req, build_auth_req, build_assoc_req,
    build_reassoc_req, build_deauth, build_disassoc,
)
from src.wlan.rates import RATE_SETS, DEFAULT_PHY, PHY_BAND

BROADCAST = "ff:ff:ff:ff:ff:ff"


# ═══════════════════════════════════════════════════════════════
# Utility functions
# ═══════════════════════════════════════════════════════════════

def random_sta_mac() -> str:
    """Generate locally administered unicast MAC: 02:xx:xx:xx:xx:xx."""
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0, 255) for _ in range(5)
    )


def normalize_mac(mac: str) -> str:
    """Validate and normalize MAC address to lowercase colon format."""
    m = mac.strip().lower()
    parts = m.split(":")
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        raise ValueError(f"Invalid MAC format: {mac}")
    int("".join(parts), 16)
    return m


def set_channel(iface: str, channel: int) -> None:
    """Set wireless interface channel via iw."""
    cmd = ["iw", "dev", iface, "set", "channel", str(channel)]
    try:
        subprocess.run(cmd, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("[WARN] iw not found, skip channel set.")
    except subprocess.CalledProcessError:
        print(f"[WARN] failed to set channel {channel} on {iface}")


def resolve_stas(args: argparse.Namespace) -> List[str]:
    if args.sta_list:
        return [normalize_mac(m) for m in args.sta_list.split(",")]
    count = args.sta_count
    if count < 1:
        raise ValueError("--sta-count must be >= 1")
    return [random_sta_mac() for _ in range(count)]


# ═══════════════════════════════════════════════════════════════
# Base sender
# ═══════════════════════════════════════════════════════════════

class WifiMgmtSender:
    """802.11 management frame injection base class.

    Subclass and override build_sequence() per test scenario.

    Supports:
      - Sequential mode: one STA at a time
      - Concurrent mode: one thread per STA with Semaphore cap
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.iface = args.iface
        self.bssid = args.ap_bssid
        self.ssid = args.ssid
        self.phy = getattr(args, "phy", DEFAULT_PHY)
        self.count = args.count
        self.interval = args.interval
        self.intra_gap = args.intra_gap
        self.verbose = args.verbose
        self.concurrent = getattr(args, "concurrent", False)
        self.max_workers = getattr(args, "max_workers", 0)

    def build_sequence(self, sta: str) -> List:
        raise NotImplementedError("Subclass must override build_sequence()")

    def _print(self, msg: str) -> None:
        if self.concurrent:
            tname = threading.current_thread().name
            print(f"[{tname}] {msg}")
        else:
            print(msg)

    def _send_one_round(self, sta: str, sta_index: int, round_num: int) -> None:
        frames = self.build_sequence(sta)
        total_label = "\u221e" if self.count == 0 else str(self.count)

        self._print(
            f"[INFO] sta[{sta_index}]={sta} round={round_num}/{total_label} "
            f"frames={len(frames)}"
        )
        for idx, pkt in enumerate(frames, start=1):
            sendp(pkt, iface=self.iface, verbose=False)
            self._print(f"  -> frame {idx}/{len(frames)} subtype={pkt[Dot11].subtype}")
            if idx < len(frames) and self.intra_gap > 0:
                time.sleep(self.intra_gap)

    def _sta_worker(self, sta: str, sta_index: int,
                    semaphore: Optional[threading.Semaphore] = None) -> None:
        try:
            if semaphore:
                semaphore.acquire()
            round_num = 0
            while True:
                round_num += 1
                self._send_one_round(sta, sta_index, round_num)
                if self.count > 0 and round_num >= self.count:
                    break
                if self.interval > 0:
                    time.sleep(self.interval)
        finally:
            if semaphore:
                semaphore.release()

    def run_sequential(self, stas: List[str]) -> int:
        total_round = 0
        try:
            while True:
                total_round += 1
                for i, sta in enumerate(stas):
                    self._send_one_round(sta, i, total_round)
                if self.count > 0 and total_round >= self.count:
                    break
                if self.interval > 0:
                    time.sleep(self.interval)
        except KeyboardInterrupt:
            print("\n[INFO] User interrupt")
            return 130
        return 0

    def run_concurrent(self, stas: List[str]) -> int:
        max_workers = self.max_workers if self.max_workers > 0 else len(stas)
        semaphore = threading.Semaphore(max_workers)
        threads: List[threading.Thread] = []
        for i, sta in enumerate(stas):
            t = threading.Thread(
                target=self._sta_worker,
                args=(sta, i, semaphore),
                name=f"sta[{i}]",
                daemon=True,
            )
            t.start()
            threads.append(t)
        try:
            for t in threads:
                while t.is_alive():
                    t.join(timeout=0.5)
        except KeyboardInterrupt:
            print("\n[INFO] User interrupt, waiting for threads...")
            for t in threads:
                t.join(timeout=2)
            return 130
        return 0

    def run(self) -> int:
        stas = resolve_stas(self.args)
        if self.bssid:
            try:
                self.bssid = normalize_mac(self.bssid)
            except ValueError as exc:
                print(f"[ERR] Invalid --ap-bssid: {exc}")
                return 2
        if self.count < 0:
            print("[ERR] --count must be >= 0")
            return 2
        conf.iface = self.iface
        conf.verb = 1 if self.verbose else 0
        if self.args.channel > 0:
            set_channel(self.iface, self.args.channel)
        mode = "\u5e76\u53d1" if self.concurrent else "\u987a\u5e8f"
        band = PHY_BAND.get(self.phy, self.phy)
        print(
            f"[INFO] mode={mode} iface={self.iface} BSSID={self.bssid} "
            f"SSID='{self.ssid}' PHY={self.phy}({band}) "
            f"STAs={len(stas)} rounds={self.count}"
        )
        for i, sta in enumerate(stas):
            print(f"  STA[{i}]: {sta}")
        if self.concurrent:
            return self.run_concurrent(stas)
        else:
            return self.run_sequential(stas)


# ═══════════════════════════════════════════════════════════════
# Built-in test scenarios
# ═══════════════════════════════════════════════════════════════

class ProbeSender(WifiMgmtSender):
    def build_sequence(self, sta):
        return [build_probe_req(sta, self.ssid, self.phy)]


class AuthSender(WifiMgmtSender):
    def build_sequence(self, sta):
        return [build_auth_req(sta, self.bssid)]


class AssocSender(WifiMgmtSender):
    def build_sequence(self, sta):
        return [build_probe_req(sta, self.ssid, self.phy),
                build_auth_req(sta, self.bssid),
                build_assoc_req(sta, self.bssid, self.ssid, phy=self.phy)]


class DeauthFloodSender(WifiMgmtSender):
    def build_sequence(self, sta):
        return [build_deauth(sta, self.bssid)]


# ═══════════════════════════════════════════════════════════════
# CLI argument setup
# ═══════════════════════════════════════════════════════════════

def add_common_args(parser: argparse.ArgumentParser,
                    ap_bssid_required: bool = True) -> None:
    parser.add_argument("--iface", required=True,
                        help="Monitor mode interface, e.g. wlan0mon")
    parser.add_argument("--ap-bssid", default=None,
                        required=ap_bssid_required,
                        help="AP BSSID (MAC address)")
    parser.add_argument("--ssid", default="",
                        help="SSID (default: broadcast probe)")
    parser.add_argument("--phy", default=DEFAULT_PHY,
                        choices=list(RATE_SETS.keys()),
                        help=f"PHY type: b/g/a (default: {DEFAULT_PHY})")
    parser.add_argument("--sta-count", type=int, default=1,
                        help="Number of random STAs (default: 1)")
    parser.add_argument("--sta-list", default="",
                        help="Comma-separated explicit STA MACs")
    parser.add_argument("--count", type=int, default=1,
                        help="Rounds per STA, 0=infinite (default: 1)")
    parser.add_argument("--interval", type=float, default=0.2,
                        help="Seconds between rounds (default: 0.2)")
    parser.add_argument("--intra-gap", type=float, default=0.02,
                        help="Seconds between frames in sequence (default: 0.02)")
    parser.add_argument("--channel", type=int, default=0,
                        help="Channel to set before sending (default: 0=skip)")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable Scapy verbose output")


def add_concurrent_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--concurrent", action="store_true",
                        help="Concurrent mode: one thread per STA")
    parser.add_argument("--max-workers", type=int, default=0,
                        help="Max concurrent threads (default: 0=unlimited)")


# ═══════════════════════════════════════════════════════════════
# Main entry
# ═══════════════════════════════════════════════════════════════

SCENARIOS = {
    "probe": ProbeSender,
    "auth": AuthSender,
    "assoc": AssocSender,
    "deauth": DeauthFloodSender,
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="WLAN management frame injection CLI — "
                    "built on wlan-scapy modular frame builders",
    )
    sub = parser.add_subparsers(dest="scenario", required=True,
                                help="Test scenario")
    for name, cls in SCENARIOS.items():
        sp = sub.add_parser(name, help=f"Run {name} scenario")
        add_common_args(sp, ap_bssid_required=(name != "probe"))
        add_concurrent_args(sp)
    args = parser.parse_args()
    sender = SCENARIOS[args.scenario](args)
    return sender.run()


if __name__ == "__main__":
    sys.exit(main())
