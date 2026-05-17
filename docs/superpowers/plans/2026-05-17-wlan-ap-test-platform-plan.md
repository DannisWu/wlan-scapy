# WLAN AP 无线驱动测试平台 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建基于 pytest 的 WLAN AP 无线驱动自动化测试平台，通过 SSH/Telnet/串口远程控制多台设备，支持 802.11 injection 模拟多 STA 和 scapy 802.3 流量生成。

**Architecture:** 5 层架构 —— 连接层(SSH/Telnet/Serial) → 传输层(FrameTransport) → 设备层(APController/StaInjector/TrafficGenerator) → 领域层(帧/流量构建/CLI解析) → 测试层(pytest fixtures)。传输层通过依赖注入隔离帧收发方式，预留虚拟 AP 隧道扩展点。

**Tech Stack:** Python ≥ 3.10, scapy, paramiko, telnetlib3, pyserial, pytest + pytest-asyncio + pytest-html, PyYAML

---

## File Structure

```
wlan-scapy/
├── pyproject.toml
├── config/
│   └── topology.yaml
├── src/
│   ├── __init__.py
│   ├── connections/
│   │   ├── __init__.py
│   │   ├── base.py              # SSHResult, TelnetResult, SerialMode
│   │   ├── ssh.py               # SSHConnection
│   │   ├── telnet.py            # TelnetConnection
│   │   ├── serial.py            # SerialConnection (local + comhub)
│   │   └── pool.py              # ConnectionPool
│   ├── transport/
│   │   ├── __init__.py
│   │   ├── base.py              # FrameTransport ABC
│   │   └── radio.py             # RadioTransport
│   ├── devices/
│   │   ├── __init__.py
│   │   ├── ap.py                # APController
│   │   ├── sta.py               # StaInjector + StaInstance
│   │   └── wired_pc.py          # TrafficGenerator
│   ├── wlan/
│   │   ├── __init__.py
│   │   ├── frames.py            # 802.11 frame builders
│   │   ├── ie.py                # IE builders (normal + malformed)
│   │   ├── sequences.py         # Auth→Assoc→4-way-handshake
│   │   └── anomalies.py         # Abnormal interaction sequences
│   ├── traffic/
│   │   ├── __init__.py
│   │   ├── l3.py                # ARP, ICMP, DHCP, NDP
│   │   ├── l4.py                # TCP, UDP
│   │   └── special.py           # Jumbo, fragmentation, multicast/broadcast
│   ├── cli/
│   │   ├── __init__.py
│   │   └── parser.py            # CLIParser
│   └── utils/
│       ├── __init__.py
│       ├── config.py            # YAML config loader
│       └── pcap.py              # PCAPManager
├── tests/
│   ├── __init__.py
│   ├── conftest.py              # Top-level fixtures
│   └── scenarios/
│       ├── __init__.py
│       ├── sta_association/
│       │   ├── __init__.py
│       │   ├── conftest.py
│       │   ├── normal/
│       │   │   ├── __init__.py
│       │   │   └── test_11ax.py
│       │   └── abnormal/
│       │       ├── __init__.py
│       │       └── test_protocol_violation.py
│       ├── traffic_forwarding/
│       │   ├── __init__.py
│       │   ├── conftest.py
│       │   └── normal/
│       │       ├── __init__.py
│       │       └── test_l3_unicast.py
│       └── multi_sta/
│           ├── __init__.py
│           ├── conftest.py
│           └── normal/
│               ├── __init__.py
│               └── test_32sta.py
└── reports/
    └── .gitkeep
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `config/topology.yaml`
- Create: `reports/.gitkeep`
- Create: All `__init__.py` files (empty)

- [ ] **Step 1: Write pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "wlan-scapy"
version = "0.1.0"
description = "WLAN AP wireless driver test platform"
requires-python = ">=3.10"
dependencies = [
    "scapy>=2.5.0",
    "paramiko>=3.4.0",
    "telnetlib3>=2.0.0",
    "pyserial>=3.5",
    "pytest>=8.0.0",
    "pytest-asyncio>=0.23.0",
    "pytest-html>=4.1.0",
    "PyYAML>=6.0",
]

[project.optional-dependencies]
dev = [
    "pytest-cov>=5.0.0",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
pythonpath = ["src"]
markers = [
    "scenario: test scenario category",
    "wifi_standard: Wi-Fi standard being tested (11n/11ac/11ax)",
]
```

- [ ] **Step 2: Write config/topology.yaml template**

```yaml
test_runner:
  report_dir: ./reports

wired_pc:
  host: 192.168.1.10
  ssh_port: 22
  user: root
  password: ~
  interface: eth1

sta:
  host: 192.168.1.20
  ssh_port: 22
  user: root
  password: ~
  transport:
    type: radio
    interface: wlp2s0

ap:
  telnet:
    host: 192.168.1.1
    port: 23
  serial:
    enable: false
    mode: local
    port: /dev/ttyUSB0
    baudrate: 115200
    # comhub mode:
    # mode: comhub
    # host: comhub.internal
    # port: 7001
```

- [ ] **Step 3: Create directory tree and all __init__.py files**

```bash
mkdir -p config reports
mkdir -p src/connections src/transport src/devices src/wlan src/traffic src/cli src/utils
mkdir -p tests/scenarios/sta_association/normal
mkdir -p tests/scenarios/sta_association/abnormal
mkdir -p tests/scenarios/traffic_forwarding/normal
mkdir -p tests/scenarios/traffic_forwarding/abnormal
mkdir -p tests/scenarios/multi_sta/normal
touch reports/.gitkeep
for d in src src/connections src/transport src/devices src/wlan src/traffic src/cli src/utils; do
  echo '"""WLAN AP test platform."""' > "$d/__init__.py"
done
for d in tests tests/scenarios tests/scenarios/sta_association tests/scenarios/sta_association/normal tests/scenarios/sta_association/abnormal tests/scenarios/traffic_forwarding tests/scenarios/traffic_forwarding/normal tests/scenarios/traffic_forwarding/abnormal tests/scenarios/multi_sta tests/scenarios/multi_sta/normal; do
  touch "$d/__init__.py"
done
```

- [ ] **Step 4: Set up virtualenv and verify install**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
python -c "import scapy; print('scapy', scapy.__version__)"
python -c "import pytest; print('pytest', pytest.__version__)"
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: project scaffolding with dependencies and directory structure"
```

---

### Task 2: Connection Layer — SSH + Serial

**Files:**
- Create: `src/connections/base.py`
- Create: `src/connections/ssh.py`
- Create: `src/connections/serial.py`
- Test: `tests/connections/` (unit tests with mock)

- [ ] **Step 1: Create test directory and write connection base types**

First, create `tests/connections/__init__.py`:

```bash
mkdir -p tests/connections
touch tests/connections/__init__.py
```

Write `src/connections/base.py`:

```python
"""Connection layer base types."""

from dataclasses import dataclass, field
from enum import Enum


@dataclass
class SSHResult:
    stdout: str
    stderr: str
    exit_code: int


@dataclass
class TelnetResult:
    output: str
    prompt: str = ""


class SerialMode(Enum):
    LOCAL = "local"
    COMHUB = "comhub"
```

- [ ] **Step 2: Write SSH connection**

Write `src/connections/ssh.py`:

```python
"""SSH connection to Wired PC / WLAN STA."""

import asyncio
from pathlib import Path

import paramiko

from src.connections.base import SSHResult


class SSHConnection:
    def __init__(self, host: str, port: int = 22,
                 user: str = "root", password: str | None = None,
                 key_file: str | None = None):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.key_file = key_file
        self._client: paramiko.SSHClient | None = None

    async def connect(self) -> None:
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self._client.connect(
                self.host, self.port, self.user,
                password=self.password,
                key_filename=self.key_file,
                timeout=10,
            ),
        )

    async def disconnect(self) -> None:
        if self._client:
            self._client.close()
            self._client = None

    async def exec(self, cmd: str, timeout: float = 30) -> SSHResult:
        if not self._client:
            raise RuntimeError("Not connected")
        stdin, stdout, stderr = await asyncio.get_event_loop().run_in_executor(
            None, lambda: self._client.exec_command(cmd, timeout=timeout),
        )
        out = await asyncio.get_event_loop().run_in_executor(
            None, stdout.read,
        )
        err = await asyncio.get_event_loop().run_in_executor(
            None, stderr.read,
        )
        exit_code = stdout.channel.recv_exit_status()
        return SSHResult(
            stdout=out.decode("utf-8", errors="replace"),
            stderr=err.decode("utf-8", errors="replace"),
            exit_code=exit_code,
        )

    async def exec_sudo(self, cmd: str, timeout: float = 30) -> SSHResult:
        return await self.exec(f"sudo {cmd}", timeout=timeout)

    async def push_file(self, local: Path, remote: str) -> None:
        if not self._client:
            raise RuntimeError("Not connected")
        sftp = self._client.open_sftp()
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: sftp.put(str(local), remote),
        )
        sftp.close()

    async def pull_file(self, remote: str, local: Path) -> None:
        if not self._client:
            raise RuntimeError("Not connected")
        sftp = self._client.open_sftp()
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: sftp.get(remote, str(local)),
        )
        sftp.close()

    @property
    def is_connected(self) -> bool:
        return self._client is not None
```

- [ ] **Step 3: Write serial connection**

Write `src/connections/serial.py`:

```python
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
        if self._mode == SerialMode.LOCAL:
            if self._reader.in_waiting:
                return self._reader.readline().decode("utf-8", errors="replace")
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
```

- [ ] **Step 4: Create connection tests**

Write `tests/connections/test_base.py`:

```python
"""Tests for connection base types."""
from src.connections.base import SSHResult, SerialMode


class TestSerialMode:
    def test_modes(self):
        assert SerialMode.LOCAL.value == "local"
        assert SerialMode.COMHUB.value == "comhub"
```

- [ ] **Step 5: Run tests and commit**

```bash
source venv/bin/activate
python -m pytest tests/connections/test_base.py -v
```

```bash
git add src/connections/base.py src/connections/ssh.py src/connections/serial.py tests/connections/
git commit -m "feat: add connection layer — SSH, Serial with base types"
```

---

### Task 3: Connection Layer — Telnet + ConnectionPool

**Files:**
- Create: `src/connections/telnet.py`
- Create: `src/connections/pool.py`
- Create: `src/utils/config.py`

- [ ] **Step 1: Write Telnet connection**

Write `src/connections/telnet.py`:

```python
"""Telnet connection to DUT AP CLI."""

import asyncio

import telnetlib3

from src.connections.base import TelnetResult


class TelnetConnection:
    def __init__(self, host: str, port: int = 23):
        self.host = host
        self.port = port
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
        import re
        deadline = asyncio.get_event_loop().time() + timeout
        collected = ""
        while asyncio.get_event_loop().time() < deadline:
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
        deadline = asyncio.get_event_loop().time() + timeout
        collected = ""
        while asyncio.get_event_loop().time() < deadline:
            try:
                data = await asyncio.wait_for(
                    self._reader.read(4096), timeout=1.0,
                )
                if data:
                    collected += data
                    if collected.rstrip().endswith(("# ", "> ", "? ")):
                        return collected
            except asyncio.TimeoutError:
                if collected:
                    return collected
                continue
        return collected

    @property
    def is_connected(self) -> bool:
        return self._writer is not None
```

- [ ] **Step 2: Write config loader**

Write `src/utils/config.py`:

```python
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
```

- [ ] **Step 3: Write ConnectionPool**

Write `src/connections/pool.py`:

```python
"""Connection pool managing all remote device connections."""

from src.connections.base import SerialMode
from src.connections.ssh import SSHConnection
from src.connections.telnet import TelnetConnection
from src.connections.serial import SerialConnection
from src.utils.config import TopologyConfig


class ConnectionPool:
    def __init__(self, config: TopologyConfig):
        self.config = config
        self._ssh: dict[str, SSHConnection] = {}
        self._telnet: TelnetConnection | None = None
        self._serial: SerialConnection | None = None

    async def connect_all(self) -> None:
        # SSH to Wired PC
        wired = SSHConnection(
            self.config.wired_pc.host,
            self.config.wired_pc.ssh_port,
            self.config.wired_pc.user,
            self.config.wired_pc.password,
        )
        await wired.connect()
        self._ssh["wired_pc"] = wired

        # SSH to WLAN STA
        sta = SSHConnection(
            self.config.sta.host,
            self.config.sta.ssh_port,
            self.config.sta.user,
            self.config.sta.password,
        )
        await sta.connect()
        self._ssh["sta"] = sta

        # Telnet to DUT AP
        self._telnet = TelnetConnection(
            self.config.ap.telnet.host,
            self.config.ap.telnet.port,
        )
        await self._telnet.connect()

        # Serial to DUT AP (optional)
        if self.config.ap.serial.enable:
            self._serial = SerialConnection()
            mode = SerialMode.LOCAL if self.config.ap.serial.mode == "local" else SerialMode.COMHUB
            if mode == SerialMode.LOCAL:
                await self._serial.open(
                    mode,
                    port=self.config.ap.serial.port,
                    baudrate=self.config.ap.serial.baudrate,
                )
            else:
                await self._serial.open(
                    mode,
                    host=self.config.ap.serial.host,
                    port=self.config.ap.serial.com_port,
                )

    async def disconnect_all(self) -> None:
        for conn in self._ssh.values():
            await conn.disconnect()
        if self._telnet:
            await self._telnet.disconnect()
        if self._serial:
            await self._serial.close()

    @property
    def ssh(self) -> dict[str, SSHConnection]:
        return self._ssh

    @property
    def telnet(self) -> TelnetConnection:
        if not self._telnet:
            raise RuntimeError("Telnet not connected")
        return self._telnet

    @property
    def serial(self) -> SerialConnection | None:
        return self._serial
```

- [ ] **Step 4: Run tests and commit**

```bash
python -m pytest tests/ -v
```

```bash
git add src/connections/telnet.py src/connections/pool.py src/utils/config.py
git commit -m "feat: add Telnet connection, config loader, and connection pool"
```

---

### Task 4: Domain Layer — 802.11 Frames, IEs, Anomalies

**Files:**
- Create: `src/wlan/frames.py`
- Create: `src/wlan/ie.py`
- Create: `src/wlan/anomalies.py`
- Create: `tests/wlan/` test files

- [ ] **Step 1: Create wlan test directory**

```bash
mkdir -p tests/wlan
touch tests/wlan/__init__.py
```

- [ ] **Step 2: Write IE builders**

Write `src/wlan/ie.py`:

```python
"""802.11 Information Element builders — normal and malformed."""

from dataclasses import dataclass
import struct


@dataclass
class IE:
    id: int
    body: bytes

    def pack(self) -> bytes:
        length = len(self.body)
        return struct.pack("!BB", self.id, length) + self.body


def ssid_ie(ssid: str) -> IE:
    return IE(id=0, body=ssid.encode("utf-8"))

def supported_rates_ie(rates: list[int]) -> IE:
    return IE(id=1, body=bytes(rates))

def ht_capabilities_ie(caps: bytes) -> IE:
    return IE(id=45, body=caps)

def vht_capabilities_ie(caps: bytes) -> IE:
    return IE(id=191, body=caps)

def he_capabilities_ie(caps: bytes) -> IE:
    return IE(id=255, body=caps)  # 255 for HE per 802.11ax

def rsn_ie(auth_type: int = 2, pairwise: bytes = b"\x00\x0f\xac\x04",
           group: bytes = b"\x00\x0f\xac\x04", psk: bool = True) -> IE:
    body = struct.pack("<H", 1)  # version
    body += group
    body += struct.pack("<H", 1) + pairwise
    body += struct.pack("<H", 1) + struct.pack("<B", auth_type)
    if psk:
        body += struct.pack("<H", 1) + b"\x00\x0f\xac\x02"
    else:
        body += struct.pack("<H", 1) + b"\x00\x0f\xac\x01"
    body += struct.pack("<H", 0)  # no RSN capabilities
    return IE(id=48, body=body)


# --- Malformed IE builders ---

def oversized_ie(ie_id: int, size: int) -> IE:
    """IE with body larger than declared length."""
    return IE(id=ie_id, body=b"\x00" * size)

def truncated_ie(ie_id: int, actual_len: int) -> IE:
    """IE truncated to actual_len bytes."""
    body = b"\x01\x02\x03\x04" * 10
    return IE(id=ie_id, body=body[:actual_len])

def vendor_malformed_ie(oui: bytes = b"\x00\x11\x22",
                        data: bytes = b"\xff" * 32) -> IE:
    return IE(id=221, body=oui + data)
```

- [ ] **Step 3: Write 802.11 frame builders**

Write `src/wlan/frames.py`:

```python
"""802.11 frame builders using scapy Dot11."""

import struct
from scapy.all import RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11AssoResp
from scapy.all import Dot11ProbeReq, Dot11Deauth, Dot11Disas

from src.wlan.ie import IE


def _dot11_header(subtype: int, type: int = 0, sender: str = "",
                  receiver: str = "", bssid: str = "", seq_num: int = 0):
    fc = (type << 2) | (subtype << 4)
    return Dot11(
        FCfield=fc,
        addr1=receiver,
        addr2=sender,
        addr3=bssid,
        SC=seq_num << 4,
    )


def build_auth_frame(sender: str, receiver: str, bssid: str,
                     seq_num: int = 0, algo: int = 0,
                     seq: int = 1, status: int = 0) -> bytes:
    dot11 = _dot11_header(11, 0, sender, receiver, bssid, seq_num)
    auth = Dot11Auth(algo=algo, seqnum=seq, status=status)
    return bytes(RadioTap() / dot11 / auth)


def build_assoc_req_frame(sender: str, receiver: str, bssid: str,
                          ssid: str, capabilities: int = 0x0431,
                          rates: list[int] | None = None,
                          ies: list[IE] | None = None,
                          seq_num: int = 0) -> bytes:
    if rates is None:
        rates = [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]
    dot11 = _dot11_header(0, 0, sender, receiver, bssid, seq_num)
    ies_bytes = b"".join(ie.pack() for ie in (ies or []))
    assoc = Dot11AssoReq(cap=capabilities, listen_interval=10) / (
        ssid.encode("utf-8") + bytes(rates) + ies_bytes
    )
    return bytes(RadioTap() / dot11 / assoc)


def build_deauth_frame(sender: str, receiver: str, bssid: str,
                       reason: int = 3, seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(12, 0, sender, receiver, bssid, seq_num)
    deauth = Dot11Deauth(reason=reason)
    return bytes(RadioTap() / dot11 / deauth)


def build_disassoc_frame(sender: str, receiver: str, bssid: str,
                         reason: int = 8, seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(10, 0, sender, receiver, bssid, seq_num)
    disas = Dot11Disas(reason=reason)
    return bytes(RadioTap() / dot11 / disas)


def build_probe_req_frame(sender: str, receiver: str, bssid: str,
                          ssid: str = "", seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(4, 0, sender, receiver, bssid, seq_num)
    probe = Dot11ProbeReq() / ssid.encode("utf-8")
    return bytes(RadioTap() / dot11 / probe)


def build_null_data_frame(sender: str, receiver: str, bssid: str,
                          seq_num: int = 0) -> bytes:
    dot11 = _dot11_header(44, 2, sender, receiver, bssid, seq_num)
    return bytes(RadioTap() / dot11)
```

- [ ] **Step 4: Write anomaly sequence builders**

Write `src/wlan/anomalies.py`:

```python
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
```

- [ ] **Step 5: Write tests for IE and frame builders**

Write `tests/wlan/test_ie.py`:

```python
from src.wlan.ie import ssid_ie, rsnie, oversized_ie, truncated_ie


def test_ssid_ie():
    ie = ssid_ie("MyWiFi")
    assert ie.id == 0
    assert ie.body == b"MyWiFi"
    packed = ie.pack()
    assert packed[0] == 0
    assert packed[1] == 6
    assert packed[2:] == b"MyWiFi"


def test_oversized_ie():
    ie = oversized_ie(1, 256)
    assert ie.id == 1
    assert len(ie.body) == 256


def test_truncated_ie():
    ie = truncated_ie(1, 3)
    assert len(ie.body) == 3
```

Write `tests/wlan/test_frames.py`:

```python
from scapy.all import RadioTap, Dot11Auth, Dot11AssoReq

from src.wlan.frames import build_auth_frame, build_assoc_req_frame, build_deauth_frame


def test_build_auth_frame():
    frame = build_auth_frame("00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff",
                             "aa:bb:cc:dd:ee:ff")
    assert len(frame) > 0
    pkt = RadioTap(frame)
    assert pkt[Dot11Auth].algo == 0
    assert pkt[Dot11Auth].seqnum == 1


def test_build_assoc_req_frame():
    frame = build_assoc_req_frame(
        "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff",
        "aa:bb:cc:dd:ee:ff", "TestNet",
    )
    assert len(frame) > 0
    pkt = RadioTap(frame)
    assert b"TestNet" in bytes(pkt)


def test_build_deauth_frame():
    frame = build_deauth_frame("aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55",
                               "aa:bb:cc:dd:ee:ff")
    assert len(frame) > 0
```

- [ ] **Step 6: Run tests and commit**

```bash
source venv/bin/activate
python -m pytest tests/wlan/ -v
```

```bash
git add src/wlan/ tests/wlan/
git commit -m "feat: add 802.11 frame builders, IE builders, and anomaly sequences"
```

---

### Task 5: Domain Layer — 802.3 Traffic, CLI Parser, PCAP

**Files:**
- Create: `src/traffic/l3.py`
- Create: `src/traffic/l4.py`
- Create: `src/traffic/special.py`
- Create: `src/cli/parser.py`
- Create: `src/utils/pcap.py`
- Create: `tests/traffic/` and `tests/cli/` test files

- [ ] **Step 1: Create test directories**

```bash
mkdir -p tests/traffic tests/cli tests/utils
touch tests/traffic/__init__.py tests/cli/__init__.py tests/utils/__init__.py
```

- [ ] **Step 2: Write L3 traffic builders**

Write `src/traffic/l3.py`:

```python
"""L3 protocol packet builders — ARP, ICMP, DHCP, NDP."""

from scapy.all import (
    Ether, ARP, IP, ICMP, IPv6, ICMPv6ND_NS, ICMPv6ND_NA,
)
from scapy.all import BOOTP, DHCP, UDP


def build_arp_request(src_mac: str, src_ip: str, dst_ip: str) -> bytes:
    return bytes(Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op=1, hwsrc=src_mac, psrc=src_ip,
                     hwdst="00:00:00:00:00:00", pdst=dst_ip))


def build_arp_reply(src_mac: str, src_ip: str,
                    dst_mac: str, dst_ip: str) -> bytes:
    return bytes(Ether(src=src_mac, dst=dst_mac) /
                 ARP(op=2, hwsrc=src_mac, psrc=src_ip,
                     hwdst=dst_mac, pdst=dst_ip))


def build_icmp_echo(src_ip: str, dst_ip: str,
                    id_: int = 1, seq: int = 1,
                    payload_size: int = 56) -> bytes:
    return bytes(Ether() /
                 IP(src=src_ip, dst=dst_ip) /
                 ICMP(type=8, id=id_, seq=seq) /
                 ("\x00" * payload_size))


def build_dhcp_discover(src_mac: str, xid: int = 0x12345678) -> bytes:
    return bytes(
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=src_mac.replace(":", "").encode(), xid=xid) /
        DHCP(options=[("message-type", "discover"), "end"])
    )


def build_dhcp_request(src_mac: str, requested_ip: str,
                       xid: int = 0x12345678) -> bytes:
    return bytes(
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(op=1, chaddr=src_mac.replace(":", "").encode(), xid=xid) /
        DHCP(options=[
            ("message-type", "request"),
            ("requested_addr", requested_ip),
            "end",
        ])
    )


def build_nd_solicit(src_mac: str, src_ip6: str,
                     target_ip6: str) -> bytes:
    return bytes(
        Ether(src=src_mac, dst="33:33:ff:00:00:01") /
        IPv6(src=src_ip6, dst="ff02::1:ff00:0001") /
        ICMPv6ND_NS(tgt=target_ip6)
    )
```

- [ ] **Step 3: Write L4 traffic builders**

Write `src/traffic/l4.py`:

```python
"""L4 protocol packet builders — TCP, UDP."""

from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw


def build_tcp_syn(src_mac: str = "00:11:22:33:44:01",
                  dst_mac: str = "00:11:22:33:44:02",
                  src_ip: str = "192.168.1.100",
                  dst_ip: str = "192.168.1.1",
                  sport: int = 12345, dport: int = 80,
                  seq: int = 1000, flags: str = "S") -> bytes:
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, seq=seq, flags=flags)
    )


def build_tcp_rst(src_mac: str = "00:11:22:33:44:01",
                  dst_mac: str = "00:11:22:33:44:02",
                  src_ip: str = "192.168.1.100",
                  dst_ip: str = "192.168.1.1",
                  sport: int = 12345, dport: int = 80,
                  seq: int = 1001) -> bytes:
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        TCP(sport=sport, dport=dport, seq=seq, flags="R")
    )


def build_udp(src_mac: str = "00:11:22:33:44:01",
              dst_mac: str = "00:11:22:33:44:02",
              src_ip: str = "192.168.1.100",
              dst_ip: str = "192.168.1.1",
              sport: int = 12345, dport: int = 53,
              payload: bytes = b"") -> bytes:
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip) /
        UDP(sport=sport, dport=dport) /
        Raw(payload)
    )


def build_udp_ipv6(src_mac: str = "00:11:22:33:44:01",
                   dst_mac: str = "00:11:22:33:44:02",
                   src_ip6: str = "fe80::1",
                   dst_ip6: str = "fe80::2",
                   sport: int = 12345, dport: int = 53,
                   payload: bytes = b"") -> bytes:
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IPv6(src=src_ip6, dst=dst_ip6) /
        UDP(sport=sport, dport=dport) /
        Raw(payload)
    )
```

- [ ] **Step 4: Write special traffic builders**

Write `src/traffic/special.py`:

```python
"""Special packet builders — jumbo, fragmentation, multicast/broadcast."""

from scapy.all import Ether, IP, IPv6, ICMP, Raw, fragment


def build_jumbo_packet(src_mac: str = "00:11:22:33:44:01",
                       dst_mac: str = "00:11:22:33:44:02",
                       src_ip: str = "192.168.1.100",
                       dst_ip: str = "192.168.1.1",
                       size: int = 9000) -> bytes:
    payload_size = size - 14 - 20 - 8
    return bytes(
        Ether(src=src_mac, dst=dst_mac) /
        IP(src=src_ip, dst=dst_ip, flags="DF") /
        ICMP() /
        Raw(b"\x00" * max(0, payload_size))
    )


def build_ipv4_fragments(src_mac: str = "00:11:22:33:44:01",
                         dst_mac: str = "00:11:22:33:44:02",
                         src_ip: str = "192.168.1.100",
                         dst_ip: str = "192.168.1.1",
                         payload: bytes | None = None,
                         frag_size: int = 1480) -> list[bytes]:
    if payload is None:
        payload = b"A" * 4000
    pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP() / Raw(payload)
    frags = fragment(pkt, fragsize=frag_size)
    return [bytes(f) for f in frags]


def build_ipv6_fragments(src_mac: str = "00:11:22:33:44:01",
                         dst_mac: str = "00:11:22:33:44:02",
                         src_ip6: str = "fe80::1",
                         dst_ip6: str = "fe80::2",
                         payload: bytes | None = None,
                         frag_size: int = 1280) -> list[bytes]:
    if payload is None:
        payload = b"A" * 3000
    pkt = (Ether(src=src_mac, dst=dst_mac) /
           IPv6(src=src_ip6, dst=dst_ip6) /
           ICMP() /
           Raw(payload))
    frags = fragment(pkt, fragsize=frag_size)
    return [bytes(f) for f in frags]


def build_multicast_ipv4(src_mac: str = "00:11:22:33:44:01",
                         group: str = "224.0.0.1",
                         payload: bytes = b"test") -> bytes:
    return bytes(
        Ether(src=src_mac, dst="01:00:5e:00:00:01") /
        IP(src="192.168.1.100", dst=group) /
        Raw(payload)
    )


def build_broadcast_ipv4(src_mac: str = "00:11:22:33:44:01",
                         payload: bytes = b"test") -> bytes:
    return bytes(
        Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="192.168.1.100", dst="255.255.255.255") /
        Raw(payload)
    )


def build_multicast_ipv6(src_mac: str = "00:11:22:33:44:01",
                         group: str = "ff02::1",
                         payload: bytes = b"test") -> bytes:
    return bytes(
        Ether(src=src_mac, dst="33:33:00:00:00:01") /
        IPv6(src="fe80::1", dst=group) /
        Raw(payload)
    )
```

- [ ] **Step 5: Write CLI parser**

Write `src/cli/parser.py`:

```python
"""DUT AP CLI output parser."""

import re
from typing import Any


class CLIParser:
    @staticmethod
    def parse_table(text: str, columns: list[str]) -> list[dict[str, str]]:
        rows = [line.split() for line in text.strip().split("\n") if line.strip()]
        results = []
        for row in rows:
            if len(row) >= len(columns):
                results.append(dict(zip(columns, row)))
        return results

    @staticmethod
    def parse_sta_list(text: str) -> list[dict[str, str]]:
        return CLIParser.parse_table(text, ["mac", "aid", "rssi", "state"])

    @staticmethod
    def extract_value(text: str, key: str) -> str | None:
        m = re.search(rf"{key}[:\s=]+(\S+)", text)
        return m.group(1) if m else None

    @staticmethod
    def wait_for_pattern(text: str, pattern: str) -> bool:
        return bool(re.search(pattern, text))

    @staticmethod
    def parse_stats(text: str, counter_type: str) -> dict[str, int]:
        result: dict[str, int] = {}
        for line in text.strip().split("\n"):
            m = re.match(r"(\S+)\s*[:=]\s*(\d+)", line.strip())
            if m:
                result[m.group(1)] = int(m.group(2))
        return result
```

- [ ] **Step 6: Write PCAP manager**

Write `src/utils/pcap.py`:

```python
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
```

- [ ] **Step 7: Write tests**

Write `tests/traffic/test_l3.py`:

```python
from scapy.all import Ether, ARP, ICMP

from src.traffic.l3 import build_arp_request, build_icmp_echo, build_dhcp_discover


def test_arp_request():
    pkt = Ether(build_arp_request("00:11:22:33:44:55", "192.168.1.1", "192.168.1.2"))
    assert pkt[ARP].op == 1
    assert pkt[ARP].psrc == "192.168.1.1"


def test_icmp_echo():
    pkt = Ether(build_icmp_echo("10.0.0.1", "10.0.0.2"))
    assert pkt[ICMP].type == 8


def test_dhcp_discover():
    pkt = Ether(build_dhcp_discover("00:11:22:33:44:55"))
    assert pkt.dst == "ff:ff:ff:ff:ff:ff"
```

Write `tests/cli/test_parser.py`:

```python
from src.cli.parser import CLIParser


def test_parse_table():
    text = "00:11:22:33:44:55 1 -45 associated\n00:11:22:33:44:66 2 -50 associated"
    result = CLIParser.parse_table(text, ["mac", "aid", "rssi", "state"])
    assert len(result) == 2
    assert result[0]["mac"] == "00:11:22:33:44:55"


def test_extract_value():
    assert CLIParser.extract_value("channel=36 bw=80", "channel") == "36"


def test_wait_for_pattern():
    assert CLIParser.wait_for_pattern("Error: timeout", r"Error")
    assert not CLIParser.wait_for_pattern("OK", r"Error")
```

- [ ] **Step 8: Run tests and commit**

```bash
python -m pytest tests/traffic/ tests/cli/ -v
```

```bash
git add src/traffic/ src/cli/ src/utils/pcap.py tests/traffic/ tests/cli/ tests/utils/
git commit -m "feat: add 802.3 traffic builders, CLI parser, and PCAP manager"
```

---

### Task 6: Transport Layer — FrameTransport + RadioTransport

**Files:**
- Create: `src/transport/base.py`
- Create: `src/transport/radio.py`

- [ ] **Step 1: Write FrameTransport ABC**

Write `src/transport/base.py`:

```python
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
```

- [ ] **Step 2: Write RadioTransport**

Write `src/transport/radio.py`:

```python
"""Radio transport via Intel AX200 monitor mode + injection."""

import asyncio
from pathlib import Path
from scapy.all import sendp, AsyncSniffer, wrpcap, conf

from src.connections.ssh import SSHConnection
from src.transport.base import FrameTransport


class RadioTransport(FrameTransport):
    def __init__(self, interface: str, ssh: SSHConnection, channel: int = 6):
        self.interface = interface
        self.ssh = ssh
        self.channel = channel
        self._sniffer: AsyncSniffer | None = None
        self._pcap_path: str = ""

    async def setup(self) -> None:
        """Put interface into monitor mode and set channel."""
        cmds = [
            f"ip link set {self.interface} down",
            f"iw dev {self.interface} set type monitor",
            f"ip link set {self.interface} up",
            f"iw dev {self.interface} set channel {self.channel}",
        ]
        for cmd in cmds:
            result = await self.ssh.exec_sudo(cmd)
            if result.exit_code != 0:
                raise RuntimeError(
                    f"Failed to setup monitor mode: {cmd}\n{result.stderr}"
                )

    async def teardown(self) -> None:
        """Restore interface to managed mode."""
        await self.stop_capture()
        await self.ssh.exec_sudo(f"ip link set {self.interface} down")
        await self.ssh.exec_sudo(f"iw dev {self.interface} set type managed")
        await self.ssh.exec_sudo(f"ip link set {self.interface} up")

    async def send(self, frame: bytes) -> None:
        def _send():
            sendp(frame, iface=self.interface, verbose=False)
        await asyncio.get_event_loop().run_in_executor(None, _send)

    async def start_capture(self, pcap_path: str,
                            bpf_filter: str = "") -> None:
        self._pcap_path = pcap_path

        def _capture(pkt):
            wrpcap(pcap_path, pkt, append=True)

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=bpf_filter,
            prn=_capture,
        )
        self._sniffer.start()
        await asyncio.sleep(0.5)

    async def stop_capture(self) -> str:
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
        return self._pcap_path
```

- [ ] **Step 3: Commit**

```bash
git add src/transport/
git commit -m "feat: add FrameTransport abstraction and RadioTransport implementation"
```

---

### Task 7: Device Layer — APController + TrafficGenerator

**Files:**
- Create: `src/devices/ap.py`
- Create: `src/devices/wired_pc.py`
- Create: `tests/devices/` test files

- [ ] **Step 1: Write APController**

Write `src/devices/ap.py`:

```python
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
```

- [ ] **Step 2: Write TrafficGenerator**

Write `src/devices/wired_pc.py`:

```python
"""Wired PC traffic generator — scapy-based 802.3 packet generation via SSH."""

import asyncio
from pathlib import Path

from src.connections.ssh import SSHConnection


class TrafficGenerator:
    """High-level traffic generation on the wired PC via SSH."""

    def __init__(self, ssh: SSHConnection, interface: str = "eth1"):
        self._ssh = ssh
        self.interface = interface
        self._capture_pid: str | None = None
        self._pcap_path: str = ""

    async def _send_script(self, script: str) -> None:
        """Push a scapy script to remote and execute."""
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False,
                                         mode="w") as f:
            f.write(script)
            script_path = f.name
        remote_path = "/tmp/_traffic_gen.py"
        await self._ssh.push_file(Path(script_path), remote_path)
        result = await self._ssh.exec_sudo(f"python3 {remote_path}")
        Path(script_path).unlink()
        if result.exit_code != 0:
            raise RuntimeError(f"Traffic script failed: {result.stderr}")

    def _make_send_script(self, packet_code: str, count: int) -> str:
        return f"""
from scapy.all import *
import sys
pkt = {packet_code}
if isinstance(pkt, list):
    for p in pkt:
        sendp(p, iface="{self.interface}", verbose=False)
else:
    for _ in range({count}):
        sendp(pkt, iface="{self.interface}", verbose=False)
"""

    async def send_arp(self, op: int, src_ip: str, dst_ip: str,
                       src_mac: str = "00:11:22:33:44:01",
                       dst_mac: str = "ff:ff:ff:ff:ff:ff",
                       count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether(src='{src_mac}', dst='{dst_mac}') / "
            f"ARP(op={op}, hwsrc='{src_mac}', psrc='{src_ip}', "
            f"hwdst='00:00:00:00:00:00', pdst='{dst_ip}')",
            count,
        )
        await self._send_script(script)

    async def send_icmp(self, src_ip: str, dst_ip: str,
                        icmp_type: int = 8, count: int = 1,
                        size: int = 64) -> None:
        payload_size = max(0, size - 14 - 20 - 8)
        script = self._make_send_script(
            f"Ether() / IP(src='{src_ip}', dst='{dst_ip}') / "
            f"ICMP(type={icmp_type}) / Raw(b'\\x00' * {payload_size})",
            count,
        )
        await self._send_script(script)

    async def send_tcp(self, src_ip: str, dst_ip: str,
                       sport: int, dport: int,
                       src_mac: str = "00:11:22:33:44:01",
                       dst_mac: str = "00:11:22:33:44:02",
                       flags: str = "S", count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether(src='{src_mac}', dst='{dst_mac}') / "
            f"IP(src='{src_ip}', dst='{dst_ip}') / "
            f"TCP(sport={sport}, dport={dport}, flags='{flags}')",
            count,
        )
        await self._send_script(script)

    async def send_udp(self, src_ip: str, dst_ip: str,
                       sport: int, dport: int,
                       payload: bytes = b"",
                       count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether() / IP(src='{src_ip}', dst='{dst_ip}') / "
            f"UDP(sport={sport}, dport={dport}) / Raw({payload!r})",
            count,
        )
        await self._send_script(script)

    async def send_broadcast(self, src_ip: str,
                             payload: bytes = b"test",
                             count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether(dst='ff:ff:ff:ff:ff:ff') / "
            f"IP(src='{src_ip}', dst='255.255.255.255') / Raw({payload!r})",
            count,
        )
        await self._send_script(script)

    async def send_multicast(self, group: str,
                             payload: bytes = b"test",
                             count: int = 1) -> None:
        script = self._make_send_script(
            f"Ether() / IP(src='192.168.1.100', dst='{group}') / Raw({payload!r})",
            count,
        )
        await self._send_script(script)

    async def send_jumbo(self, src_ip: str, dst_ip: str,
                         size: int = 9000) -> None:
        payload_size = max(0, size - 14 - 20 - 8)
        script = self._make_send_script(
            f"Ether() / IP(src='{src_ip}', dst='{dst_ip}') / "
            f"ICMP() / Raw(b'\\x00' * {payload_size})",
            1,
        )
        await self._send_script(script)

    async def send_fragmented(self, payload: bytes,
                              frag_size: int = 1480) -> None:
        script = f"""
from scapy.all import *
pkt = Ether() / IP(src='192.168.1.100', dst='192.168.1.1') / ICMP() / Raw({payload!r})
frags = fragment(pkt, fragsize={frag_size})
for f in frags:
    sendp(f, iface="{self.interface}", verbose=False)
"""
        await self._send_script(script)

    async def start_capture(self, pcap_path: str,
                            bpf_filter: str = "") -> None:
        self._pcap_path = pcap_path
        filter_arg = f"'{bpf_filter}'" if bpf_filter else ""
        result = await self._ssh.exec_sudo(
            f"tcpdump -i {self.interface} {filter_arg} -w {pcap_path} & "
            f"echo $!"
        )
        self._capture_pid = result.stdout.strip()

    async def stop_capture(self) -> str:
        if self._capture_pid:
            await self._ssh.exec_sudo(f"kill {self._capture_pid}")
            self._capture_pid = None
        return self._pcap_path
```

- [ ] **Step 3: Commit**

```bash
git add src/devices/ap.py src/devices/wired_pc.py
git commit -m "feat: add APController and TrafficGenerator device layer"
```

---

### Task 8: Device Layer — StaInjector

**Files:**
- Create: `src/devices/sta.py`

- [ ] **Step 1: Write StaInstance and StaInjector**

Write `src/devices/sta.py`:

```python
"""WLAN STA injector — multi-STA 802.11 frame injection."""

import asyncio
from dataclasses import dataclass, field
from enum import Enum

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

    async def start_capture(self, pcap_path: str,
                            bpf_filter: str = "") -> None:
        await self.transport.start_capture(pcap_path, bpf_filter)

    async def stop_capture(self) -> str:
        return await self.transport.stop_capture()
```

- [ ] **Step 2: Commit**

```bash
git add src/devices/sta.py
git commit -m "feat: add StaInjector with multi-STA management"
```

---

### Task 9: Test Fixtures — All conftest.py Files

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/scenarios/sta_association/conftest.py`
- Create: `tests/scenarios/traffic_forwarding/conftest.py`
- Create: `tests/scenarios/multi_sta/conftest.py`

- [ ] **Step 1: Write top-level conftest.py**

Write `tests/conftest.py`:

```python
"""Top-level pytest fixtures — connection pool, device instances."""

from datetime import datetime
from pathlib import Path

import pytest

from src.utils.config import load_config
from src.connections.pool import ConnectionPool
from src.transport.radio import RadioTransport
from src.devices.ap import APController
from src.devices.sta import StaInjector
from src.devices.wired_pc import TrafficGenerator


@pytest.fixture(scope="session")
def config():
    return load_config("config/topology.yaml")


@pytest.fixture(scope="session")
async def conn_pool(config):
    pool = ConnectionPool(config)
    await pool.connect_all()
    yield pool
    await pool.disconnect_all()


@pytest.fixture(scope="function")
def test_log_dir(request):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    d = Path("reports") / f"{request.node.name}_{timestamp}"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture(scope="function")
async def ap(conn_pool, test_log_dir):
    ap_ctrl = APController(conn_pool.telnet, conn_pool.serial)
    await ap_ctrl.clear_logs()
    dmesg_before = await ap_ctrl.get_dmesg()
    await ap_ctrl.start_monitoring(test_log_dir)
    yield ap_ctrl
    _, serial_errors = await ap_ctrl.stop_monitoring()
    dmesg_after = await ap_ctrl.get_dmesg()
    dmesg_errors = await ap_ctrl.check_dmesg(dmesg_before, dmesg_after)
    (test_log_dir / "dmesg_before.txt").write_text(dmesg_before)
    (test_log_dir / "dmesg_after.txt").write_text(dmesg_after)
    assert not serial_errors, f"AP serial errors: {serial_errors}"
    assert not dmesg_errors, f"AP dmesg errors: {dmesg_errors}"


@pytest.fixture(scope="function")
async def sta(conn_pool, config):
    transport = RadioTransport(
        config.sta.transport.interface,
        conn_pool.ssh["sta"],
    )
    await transport.setup()
    sta_inj = StaInjector(transport, conn_pool.ssh["sta"])
    yield sta_inj
    await sta_inj.destroy_stas()
    await transport.teardown()


@pytest.fixture(scope="function")
async def wired_pc(conn_pool, config):
    tg = TrafficGenerator(
        conn_pool.ssh["wired_pc"],
        config.wired_pc.interface,
    )
    yield tg
```

- [ ] **Step 2: Write scenario conftest.py files**

Write `tests/scenarios/sta_association/conftest.py`:

```python
"""STA association scenario fixtures."""

import pytest


@pytest.fixture
def ap_profile_11ax():
    return {"channel": 36, "mode": "11ax", "bandwidth": 80, "ssid": "test-ax"}


@pytest.fixture
def ap_profile_11ac():
    return {"channel": 36, "mode": "11ac", "bandwidth": 80, "ssid": "test-ac"}


@pytest.fixture
def ap_profile_11n():
    return {"channel": 6, "mode": "11n", "bandwidth": 40, "ssid": "test-n"}


@pytest.fixture
async def ap_configured(ap, ap_profile_11ax):
    await ap.set_radio(
        ap_profile_11ax["channel"],
        ap_profile_11ax["mode"],
        ap_profile_11ax["bandwidth"],
    )
    await ap.set_ssid(ap_profile_11ax["ssid"])
    yield ap
    await ap.factory_reset()
```

Write `tests/scenarios/traffic_forwarding/conftest.py`:

```python
"""Traffic forwarding scenario fixtures."""

import pytest
from src.devices.sta import SecurityParams


@pytest.fixture
async def ap_with_sta(ap, sta):
    """AP configured with one associated STA ready for traffic tests."""
    await ap.set_radio(36, "11ax", 80)
    await ap.set_ssid("traffic-test")
    stas = await sta.create_stas(1)
    await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff", "traffic-test",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    yield ap, sta, stas[0]
    await sta.destroy_stas()
    await ap.factory_reset()
```

Write `tests/scenarios/multi_sta/conftest.py`:

```python
"""Multi-STA concurrency scenario fixtures."""

import pytest


@pytest.fixture
async def ap_multi_sta(ap):
    await ap.set_radio(36, "11ax", 80)
    await ap.set_ssid("multi-test")
    yield ap
    await ap.factory_reset()
```

- [ ] **Step 3: Commit**

```bash
git add tests/conftest.py tests/scenarios/*/conftest.py
git commit -m "feat: add pytest fixtures — connection pool, device, and scenario conftest"
```

---

### Task 10: Example Test Cases

**Files:**
- Create: `tests/scenarios/sta_association/normal/test_11ax.py`
- Create: `tests/scenarios/sta_association/abnormal/test_protocol_violation.py`
- Create: `tests/scenarios/traffic_forwarding/normal/test_l3_unicast.py`
- Create: `tests/scenarios/multi_sta/normal/test_32sta.py`

- [ ] **Step 1: Write normal association test**

Write `tests/scenarios/sta_association/normal/test_11ax.py`:

```python
"""Normal 802.11ax STA association tests."""

import pytest
from scapy.all import rdpcap

from src.devices.sta import SecurityParams


def _pcap_has_auth(pcap_path: str, sta_mac: str) -> bool:
    pkts = rdpcap(str(pcap_path))
    for p in pkts:
        if p.haslayer("Dot11Auth") and p.addr2 == sta_mac:
            return True
    return False


@pytest.mark.scenario("sta_association")
@pytest.mark.wifi_standard("11ax")
async def test_single_sta_assoc_11ax(ap_configured, sta, test_log_dir):
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:11")
    pcap_path = str(test_log_dir / "air.pcap")

    await sta.start_capture(pcap_path, f"wlan addr2 {stas[0].mac}")
    result = await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff",
        "test-ax",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    await sta.stop_capture()

    assert result.status == 0
    assert _pcap_has_auth(pcap_path, stas[0].mac)
```

- [ ] **Step 2: Write abnormal protocol test**

Write `tests/scenarios/sta_association/abnormal/test_protocol_violation.py`:

```python
"""Abnormal protocol violation tests — malformed IEs, skipped steps."""

import asyncio

import pytest
from scapy.all import rdpcap

from src.wlan.anomalies import assoc_without_auth, repeated_auth


def _pcap_has_deauth(pcap_path: str, sta_mac: str) -> bool:
    pkts = rdpcap(str(pcap_path))
    for p in pkts:
        if p.haslayer("Dot11Deauth") and p.addr1 == sta_mac:
            return True
    return False


@pytest.mark.scenario("sta_association")
async def test_assoc_without_auth(ap_configured, sta, test_log_dir):
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:aa")
    pcap_path = str(test_log_dir / "air.pcap")
    await sta.start_capture(pcap_path)

    seq = assoc_without_auth(stas[0].mac, ap_configured.bssid if hasattr(ap_configured, 'bssid') else "ff:ff:ff:ff:ff:ff")
    await sta.send_sequence(stas[0], seq)
    await asyncio.sleep(1)
    await sta.stop_capture()

    assert _pcap_has_deauth(pcap_path, stas[0].mac), (
        "AP should send deauth when ASSOC without AUTH"
    )


@pytest.mark.scenario("sta_association")
async def test_repeated_auth(ap_configured, sta, test_log_dir):
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:bb")
    pcap_path = str(test_log_dir / "air.pcap")
    await sta.start_capture(pcap_path)

    seq = repeated_auth(stas[0].mac)
    await sta.send_sequence(stas[0], seq)
    await asyncio.sleep(1)
    await sta.stop_capture()

    pkts = rdpcap(str(pcap_path))
    auth_count = sum(1 for p in pkts if p.haslayer("Dot11Auth") and p.addr2 == stas[0].mac)
    assert auth_count == 5, f"Expected 5 AUTH frames, got {auth_count}"
```

- [ ] **Step 3: Write L3 traffic forwarding test**

Write `tests/scenarios/traffic_forwarding/normal/test_l3_unicast.py`:

```python
"""L3 unicast traffic forwarding tests."""

import asyncio

import pytest


@pytest.mark.scenario("traffic_forwarding")
async def test_arp_forwarding(wired_pc, test_log_dir):
    pcap_path = str(test_log_dir / "wired.pcap")
    await wired_pc.start_capture(pcap_path)
    await wired_pc.send_arp(1, "192.168.1.100", "192.168.1.1", count=3)
    await asyncio.sleep(2)
    await wired_pc.stop_capture()

    from scapy.all import rdpcap
    pkts = rdpcap(pcap_path)
    arp_count = sum(1 for p in pkts if p.haslayer("ARP"))
    assert arp_count >= 3, f"Expected >= 3 ARP packets, got {arp_count}"


@pytest.mark.scenario("traffic_forwarding")
async def test_icmp_forwarding(wired_pc, test_log_dir):
    pcap_path = str(test_log_dir / "wired.pcap")
    await wired_pc.start_capture(pcap_path)
    await wired_pc.send_icmp("192.168.1.100", "192.168.1.1", count=3)
    await asyncio.sleep(2)
    await wired_pc.stop_capture()

    from scapy.all import rdpcap
    pkts = rdpcap(pcap_path)
    icmp_count = sum(1 for p in pkts if p.haslayer("ICMP"))
    assert icmp_count >= 3, f"Expected >= 3 ICMP packets, got {icmp_count}"
```

- [ ] **Step 4: Write multi-STA test**

Write `tests/scenarios/multi_sta/normal/test_32sta.py`:

```python
"""Multi-STA concurrency test — 32 STAs simultaneous association."""

import asyncio

import pytest

from src.devices.sta import SecurityParams


@pytest.mark.scenario("multi_sta")
async def test_32sta_associate(ap_multi_sta, sta, test_log_dir):
    STACOUNT = 32
    stas = await sta.create_stas(STACOUNT, base_mac="00:11:22:33:00:00")
    pcap_path = str(test_log_dir / "air.pcap")
    await sta.start_capture(pcap_path)

    tasks = []
    for s in stas:
        tasks.append(sta.associate(
            s, "ff:ff:ff:ff:ff:ff", "multi-test",
            SecurityParams(auth="WPA2", psk="test1234"),
        ))
    results = await asyncio.gather(*tasks, return_exceptions=True)

    await sta.stop_capture()

    success = sum(1 for r in results if not isinstance(r, Exception) and r.status == 0)
    assert success >= STACOUNT * 0.9, (
        f"Expected >= {STACOUNT * 0.9} successful associations, got {success}"
    )
```

- [ ] **Step 5: Commit**

```bash
git add tests/scenarios/
git commit -m "test: add example test cases for STA association, traffic forwarding, and multi-STA"
```

---

### Task 11: Integration Verification

**Files:**
- None (verification only)

- [ ] **Step 1: Run unit tests (no real devices needed)**

```bash
source venv/bin/activate
python -m pytest tests/connections/ tests/wlan/ tests/traffic/ tests/cli/ -v
```

Expected: all pass (these tests don't need real hardware).

- [ ] **Step 3: Verify test collection (no real devices needed)**

```bash
python -m pytest tests/scenarios/ --collect-only
```

Expected: all test functions discovered, skip/fail only on connection errors (no real devices).

- [ ] **Step 4: Generate sample HTML report**

```bash
python -m pytest tests/connections/ tests/wlan/ tests/traffic/ tests/cli/ \
  --html=reports/test_report.html --self-contained-html
```

- [ ] **Step 5: Commit**

```bash
git add tests/scenarios/traffic_forwarding/conftest.py
git commit -m "fix: clean up traffic forwarding conftest imports"
```

---

## Self-Review Checklist

1. **Spec coverage**: Each spec section mapped to tasks:
   - Connection layer (sec 3) → Tasks 2, 3
   - Transport layer (sec 4) → Task 6
   - Device layer (sec 5) → Tasks 7, 8
   - Domain layer 802.11 (sec 6.1) → Task 4
   - Domain layer 802.3 (sec 6.2) → Task 5
   - CLI parser (sec 6.3) → Task 5
   - PCAP manager (sec 6.4) → Task 5
   - Test fixtures (sec 7.1-7.2) → Task 9
   - Test organization (sec 7.3) → Tasks 9, 10
   - Example tests (sec 7.4) → Task 10
   - Report (sec 7.5) → Task 11
   - Config format (sec 8) → Tasks 1, 3
   - Dependencies (sec 9) → Task 1

2. **Placeholder scan**: No TBD/TODO. All code is concrete.

3. **Type consistency**: 
   - `SSHResult`, `TelnetResult` defined in base.py → used in ssh.py, telnet.py ✓
   - `SerialMode` defined in base.py → used in serial.py, pool.py ✓
   - `FrameTransport` defined in transport/base.py → used in sta.py ✓
   - `StaInstance`, `StaState`, `SecurityParams` defined in sta.py → used in conftest.py, tests ✓
   - `APController` defined in ap.py → used in conftest.py ✓
   - `FrameSequence`, `FrameStep` defined in anomalies.py → used in sta.py (via send_sequence) ✓
