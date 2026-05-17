# WLAN Sniffer 角色 — 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 新增独立的 WLAN Sniffer 角色，负责空口被动抓包，与 STA injection 隔离；sniffer 为可选角色，未配置时自动跳过。

**Architecture:** 新增 `SnifferDevice` 设备类，复用 SSH 远程 tcpdump 模式；`host=""` 表示角色未启用，连接池跳过该连接，fixture 返回 `None`。

**Tech Stack:** 复用现有 paramiko (SSH) + tcpdump + scapy (分析)

---

### Task 1: Config + ConnectionPool — 可选 Sniffer 配置和连接

**Files:**
- Modify: `src/utils/config.py`
- Modify: `src/connections/pool.py`
- Modify: `config/topology.yaml`

- [ ] **Step 1: Add SnifferConfig to config.py**

Read `src/utils/config.py`, add after `STAConfig`:

```python
@dataclass
class SnifferConfig:
    host: str = ""
    ssh_port: int = 22
    user: str = "root"
    password: str | None = None
    interface: str = "wlan1mon"
```

Update `TopologyConfig` to include sniffer:

```python
@dataclass
class TopologyConfig:
    test_runner: TestRunnerConfig
    wired_pc: WiredPCConfig
    sta: STAConfig
    sniffer: SnifferConfig = field(default_factory=SnifferConfig)
    ap: APConfig
```

Update `_validate_required()`:

```python
def _validate_required(config: TopologyConfig) -> None:
    checks = [
        ("wired_pc.host", config.wired_pc.host),
        ("sta.host", config.sta.host),
        ("ap.telnet.host", config.ap.telnet.host),
    ]
    if config.sniffer.host:
        checks.append(("sniffer.host", config.sniffer.host))
    missing = [name for name, val in checks if not val]
    if missing:
        raise ValueError(f"Missing required: {', '.join(missing)}")
```

Update `load_config()` to parse sniffer section:

```python
config = TopologyConfig(
    test_runner=TestRunnerConfig(**raw.get("test_runner", {})),
    wired_pc=WiredPCConfig(**raw.get("wired_pc", {})),
    sta=STAConfig(
        **{k: v for k, v in sta_config.items() if k != "transport"},
        transport=STATransportConfig(**sta_config.get("transport", {})),
    ),
    sniffer=SnifferConfig(**raw.get("sniffer", {})),
    ap=APConfig(
        telnet=APTelnetConfig(**raw.get("ap", {}).get("telnet", {})),
        serial=APSerialConfig(**raw.get("ap", {}).get("serial", {})),
    ),
)
```

- [ ] **Step 2: Add sniffer SSH to pool.py**

Read `src/connections/pool.py`, add after the STA SSH block in `connect_all()`:

```python
# SSH to WLAN Sniffer (optional)
if self.config.sniffer.host:
    sniffer_conn = SSHConnection(
        self.config.sniffer.host,
        self.config.sniffer.ssh_port,
        self.config.sniffer.user,
        self.config.sniffer.password,
    )
    await sniffer_conn.connect()
    self._ssh["sniffer"] = sniffer_conn
```

- [ ] **Step 3: Add sniffer section to topology.yaml template**

Read `config/topology.yaml`, add after the `sta` section:

```yaml
sniffer:
  host: ""
  ssh_port: 22
  user: root
  password: ~
  interface: wlan1mon
```

- [ ] **Step 4: Run config load test and commit**

```bash
source venv/bin/activate
python -c "
from src.utils.config import load_config
cfg = load_config('config/topology.yaml')
print(f'wired={cfg.wired_pc.host} sta={cfg.sta.host} ap={cfg.ap.telnet.host}')
print(f'sniffer host=({cfg.sniffer.host}) enabled={bool(cfg.sniffer.host)}')
"
```

```bash
git add src/utils/config.py src/connections/pool.py config/topology.yaml
git commit -m "feat: add SnifferConfig and optional sniffer SSH connection"
```

---

### Task 2: SnifferDevice + Fixture

**Files:**
- Create: `src/devices/sniffer.py`
- Modify: `tests/conftest.py`
- Create: `tests/devices/test_sniffer.py`

- [ ] **Step 1: Write SnifferDevice**

Write `src/devices/sniffer.py`:

```python
"""WLAN Sniffer — passive 802.11 air capture via remote tcpdump."""

import time
from pathlib import Path

from src.connections.ssh import SSHConnection


class SnifferDevice:
    """Independent 802.11 air capture — passively monitors, never injects."""

    def __init__(self, ssh: SSHConnection, interface: str):
        self._ssh = ssh
        self.interface = interface
        self._capture_pid: str | None = None
        self._pcap_remote: str = ""

    async def setup(self, channel: int) -> None:
        """Put interface into monitor mode and set channel."""
        cmds = [
            f"ip link set {self.interface} down",
            f"iw dev {self.interface} set type monitor",
            f"ip link set {self.interface} up",
            f"iw dev {self.interface} set channel {channel}",
        ]
        for cmd in cmds:
            result = await self._ssh.exec_sudo(cmd)
            if result.exit_code != 0:
                raise RuntimeError(
                    f"Sniffer setup failed: {cmd}\n{result.stderr}"
                )

    async def teardown(self) -> None:
        """Stop capture and restore interface to managed mode."""
        await self.stop_capture()
        for cmd in [
            f"ip link set {self.interface} down",
            f"iw dev {self.interface} set type managed",
            f"ip link set {self.interface} up",
        ]:
            await self._ssh.exec_sudo(cmd)

    async def start_capture(self, pcap_path: Path,
                            bpf_filter: str = "") -> None:
        """Start remote tcpdump in background."""
        self._pcap_remote = f"/tmp/sniffer_{_timestamp()}.pcap"
        filter_arg = f"'{bpf_filter}'" if bpf_filter else ""
        result = await self._ssh.exec_sudo(
            f"tcpdump -i {self.interface} {filter_arg} "
            f"-w {self._pcap_remote} -U & echo $!"
        )
        if result.exit_code != 0:
            raise RuntimeError(
                f"Sniffer capture start failed: {result.stderr}"
            )
        self._capture_pid = result.stdout.strip()

    async def stop_capture(self) -> Path:
        """Stop tcpdump and pull pcap to local."""
        if self._capture_pid:
            await self._ssh.exec_sudo(f"kill {self._capture_pid}")
            self._capture_pid = None
        local = Path(f"/tmp/_sniffer_{_timestamp()}.pcap")
        await self._ssh.pull_file(self._pcap_remote, local)
        return local


def _timestamp() -> str:
    return time.strftime("%Y%m%d_%H%M%S")
```

- [ ] **Step 2: Add sniffer fixture to conftest.py**

Read `tests/conftest.py`, add after `wired_pc` fixture:

```python
from src.devices.sniffer import SnifferDevice


@pytest.fixture(scope="function")
async def sniffer(conn_pool, config):
    if "sniffer" not in conn_pool.ssh:
        yield None
        return
    device = SnifferDevice(
        conn_pool.ssh["sniffer"],
        config.sniffer.interface,
    )
    yield device
    await device.teardown()
```

- [ ] **Step 3: Write unit test for SnifferDevice**

Write `tests/devices/test_sniffer.py`:

```python
"""Unit tests for SnifferDevice."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from src.devices.sniffer import SnifferDevice
from src.connections.base import SSHResult


class TestSnifferDevice:
    @pytest.fixture
    def mock_ssh(self):
        ssh = MagicMock()
        ssh.exec_sudo = AsyncMock(return_value=SSHResult("", "", 0))
        return ssh

    @pytest.fixture
    def sniffer(self, mock_ssh):
        return SnifferDevice(mock_ssh, "wlan1mon")

    async def test_setup_success(self, sniffer, mock_ssh):
        await sniffer.setup(channel=36)
        calls = [c[0][0] for c in mock_ssh.exec_sudo.call_args_list]
        assert any("set type monitor" in c for c in calls)
        assert any("set channel 36" in c for c in calls)

    async def test_setup_failure_raises(self, sniffer, mock_ssh):
        mock_ssh.exec_sudo.return_value = SSHResult("", "Busy", 1)
        with pytest.raises(RuntimeError, match="Sniffer setup failed"):
            await sniffer.setup(channel=6)

    async def test_start_capture_gets_pid(self, sniffer, mock_ssh):
        mock_ssh.exec_sudo.return_value = SSHResult("12345\n", "", 0)
        await sniffer.start_capture(Path("/tmp/test.pcap"))
        assert sniffer._capture_pid == "12345"
        assert sniffer._pcap_remote != ""

    async def test_stop_capture_kills_pid(self, sniffer, mock_ssh):
        sniffer._capture_pid = "12345"
        sniffer._pcap_remote = "/tmp/sniffer_test.pcap"
        mock_ssh.pull_file = AsyncMock()
        await sniffer.stop_capture()
        assert sniffer._capture_pid is None
        mock_ssh.pull_file.assert_called_once()

    async def test_teardown_stops_capture_and_restores(self, sniffer, mock_ssh):
        sniffer._capture_pid = "12345"
        sniffer._pcap_remote = "/tmp/sniffer_test.pcap"
        mock_ssh.pull_file = AsyncMock()
        await sniffer.teardown()
        calls = [c[0][0] for c in mock_ssh.exec_sudo.call_args_list]
        assert any("set type managed" in c for c in calls)
```

- [ ] **Step 4: Run tests and commit**

```bash
source venv/bin/activate
python -m pytest tests/devices/test_sniffer.py tests/connections/ tests/wlan/ tests/traffic/ tests/cli/ tests/utils/ -v
```

Expected: all pass (~80 tests, no regressions).

```bash
git add src/devices/sniffer.py tests/conftest.py tests/devices/
git commit -m "feat: add SnifferDevice with optional sniffer fixture"
```

---

### Self-Review

1. **Spec coverage:**
   - Config layer (spec 3.1) → Task 1 Steps 1,4
   - Connection pool (spec 3.2) → Task 1 Step 2
   - SnifferDevice (spec 3.3) → Task 2 Step 1
   - Fixture (spec 3.4) → Task 2 Step 2
   - Config template (spec 3.5) → Task 1 Step 3
   - Optional role pattern → Task 1 Step 1 (SnifferConfig host=""), Task 2 Step 2 (fixture returns None)

2. **Placeholder scan:** No TBD/TODO. All code is concrete.

3. **Type consistency:**
   - `SnifferConfig(host="")` default → pool.py checks `config.sniffer.host` → fixture checks `"sniffer" in conn_pool.ssh` ✓
   - `SnifferDevice(ssh, interface)` → fixture passes `conn_pool.ssh["sniffer"]`, `config.sniffer.interface` ✓
   - `setup(channel: int)` matches spec ✓
