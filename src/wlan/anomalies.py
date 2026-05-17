"""Abnormal 802.11 interaction sequences."""

from dataclasses import dataclass, field
from src.wlan.frames import (
    build_auth_frame, build_assoc_req_frame, build_deauth_frame,
)

DEFAULT_BSSID = "ff:ff:ff:ff:ff:ff"
DEFAULT_SSID = "test-ssid"


@dataclass
class FrameStep:
    frame: bytes
    delay: float = 0.0
    expect: str | None = None


@dataclass
class FrameSequence:
    steps: list[FrameStep] = field(default_factory=list)


def assoc_without_auth(sender: str, receiver: str = DEFAULT_BSSID,
                       bssid: str = DEFAULT_BSSID,
                       ssid: str = DEFAULT_SSID) -> FrameSequence:
    return FrameSequence(steps=[
        FrameStep(
            build_assoc_req_frame(sender, receiver, bssid, ssid, seq_num=0),
            expect="deauth",
        ),
    ])


def repeated_auth(sender: str, receiver: str = DEFAULT_BSSID,
                  bssid: str = DEFAULT_BSSID, count: int = 5) -> FrameSequence:
    steps = []
    for i in range(count):
        steps.append(FrameStep(
            build_auth_frame(sender, receiver, bssid, seq_num=i, seq=1),
            delay=0.1,
        ))
    return FrameSequence(steps=steps)


def deauth_during_4way(sender: str, receiver: str = DEFAULT_BSSID,
                       bssid: str = DEFAULT_BSSID) -> FrameSequence:
    return FrameSequence(steps=[
        FrameStep(build_auth_frame(sender, receiver, bssid, seq_num=0, seq=1), delay=0.05),
        FrameStep(build_auth_frame(sender, receiver, bssid, seq_num=1, seq=2), delay=0.05),
        FrameStep(build_assoc_req_frame(sender, receiver, bssid, DEFAULT_SSID, seq_num=2), delay=0.05),
        FrameStep(build_deauth_frame(sender, receiver, bssid, reason=1), delay=0.01),
    ])


def wrong_seq_num(sender: str, receiver: str = DEFAULT_BSSID,
                  bssid: str = DEFAULT_BSSID) -> FrameSequence:
    return FrameSequence(steps=[
        FrameStep(build_auth_frame(sender, receiver, bssid, seq_num=0, seq=1)),
        FrameStep(build_auth_frame(sender, receiver, bssid, seq_num=2, seq=2)),
        FrameStep(build_auth_frame(sender, receiver, bssid, seq_num=1, seq=3)),
    ])
