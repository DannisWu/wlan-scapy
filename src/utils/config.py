"""YAML configuration loader."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class WiredPCConfig:
    host: str
    ssh_port: int = 22
    user: str = "root"
    password: str | None = None
    interface: str = "eth1"


@dataclass
class STATransportConfig:
    type: str = "radio"
    interface: str = "wlp2s0"


@dataclass
class STAConfig:
    host: str
    ssh_port: int = 22
    user: str = "root"
    password: str | None = None
    transport: STATransportConfig = field(default_factory=STATransportConfig)


@dataclass
class APTelnetConfig:
    host: str
    port: int = 23


@dataclass
class APSerialConfig:
    enable: bool = False
    mode: str = "local"
    port: str = "/dev/ttyUSB0"
    baudrate: int = 115200
    host: str = ""
    com_port: int = 7001


@dataclass
class APConfig:
    telnet: APTelnetConfig
    serial: APSerialConfig = field(default_factory=APSerialConfig)


@dataclass
class TestRunnerConfig:
    report_dir: str = "./reports"


@dataclass
class TopologyConfig:
    test_runner: TestRunnerConfig
    wired_pc: WiredPCConfig
    sta: STAConfig
    ap: APConfig


def load_config(path: str | Path) -> TopologyConfig:
    with open(path) as f:
        raw = yaml.safe_load(f)
    return TopologyConfig(
        test_runner=TestRunnerConfig(**raw.get("test_runner", {})),
        wired_pc=WiredPCConfig(**raw.get("wired_pc", {})),
        sta=STAConfig(
            **{k: v for k, v in raw.get("sta", {}).items() if k != "transport"},
            transport=STATransportConfig(**raw.get("sta", {}).get("transport", {})),
        ),
        ap=APConfig(
            telnet=APTelnetConfig(**raw.get("ap", {}).get("telnet", {})),
            serial=APSerialConfig(**raw.get("ap", {}).get("serial", {})),
        ),
    )
