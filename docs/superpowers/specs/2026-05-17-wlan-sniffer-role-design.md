# WLAN Sniffer 角色 — 设计文档

**日期**: 2026-05-17
**状态**: 已确认

## 1. 动机

当前 WLAN STA 设备同时承担 802.11 injection 和空口抓包两个职责。在 Intel AX210 等不支持 active monitor 的网卡上，注入帧仅出现在本地 pcap（回环），无法区分"真正发射到空口的帧"和"仅在本地缓冲区的帧"。

增设独立的 WLAN Sniffer 角色，将抓包与注入分离，用独立的 WiFi 接口被动监听空口，提供无干扰的 802.11 交互验证。

## 2. 架构

```
Test Runner (pytest)
    │
    ├── SSH ──► Wired PC       (scapy 802.3 流量生成)
    ├── SSH ──► WLAN STA       (802.11 injection, 多 STA 模拟)
    ├── SSH ──► WLAN Sniffer   (空口被动抓包)           ← 新增
    ├── Telnet ──► DUT AP      (CLI 配置/状态查询)
    └── Serial ──► DUT AP      (异常日志监听, 可选)
```

### 2.1 角色部署灵活性

所有角色不强制独立物理设备——可部署在同一台机器上，也可分散在不同机器上。只需在 `config/topology.yaml` 中按实际拓扑配置各角色的 `host` 即可。例如：

```yaml
# 全部在同一台机器
wired_pc:  { host: 192.168.100.28, interface: enp0s31f6 }
sta:       { host: 192.168.100.28, interface: wlp45s0 }
sniffer:   { host: 192.168.100.28, interface: wlan1mon }   # USB 网卡

# 或者分散部署
wired_pc:  { host: 10.0.0.10, ... }
sta:       { host: 10.0.0.20, ... }
sniffer:   { host: 10.0.0.30, ... }
```

框架不做限制。

## 3. 变更清单

### 3.1 配置层 (`src/utils/config.py`)

新增 `SnifferConfig`：

```python
@dataclass
class SnifferConfig:
    host: str
    ssh_port: int = 22
    user: str = "root"
    password: str | None = None
    interface: str = "wlan1mon"
```

`TopologyConfig` 新增字段：

```python
@dataclass
class TopologyConfig:
    test_runner: TestRunnerConfig
    wired_pc: WiredPCConfig
    sta: STAConfig
    sniffer: SnifferConfig          # 新增
    ap: APConfig
```

`_validate_required()` 新增 sniffer 校验：

```python
required = {
    "wired_pc.host": config.wired_pc.host,
    "sta.host": config.sta.host,
    "sniffer.host": config.sniffer.host,    # 新增
    "ap.telnet.host": config.ap.telnet.host,
}
```

### 3.2 连接池 (`src/connections/pool.py`)

`connect_all()` 新增 sniffer SSH 连接：

```python
# SSH to WLAN Sniffer
sniffer_conn = SSHConnection(
    self.config.sniffer.host,
    self.config.sniffer.ssh_port,
    self.config.sniffer.user,
    self.config.sniffer.password,
)
await sniffer_conn.connect()
self._ssh["sniffer"] = sniffer_conn
```

### 3.3 SnifferDevice (`src/devices/sniffer.py`)

新建文件，纯抓包设备：

```python
class SnifferDevice:
    """独立空口抓包 —— 仅被动监听，不注入帧"""

    def __init__(self, ssh: SSHConnection, interface: str):
        self._ssh = ssh
        self.interface = interface
        self._capture_pid: str | None = None
        self._pcap_remote: str = ""

    async def setup(self, channel: int) -> None:
        """切 monitor 模式 + 设信道"""
        cmds = [
            f"ip link set {self.interface} down",
            f"iw dev {self.interface} set type monitor",
            f"ip link set {self.interface} up",
            f"iw dev {self.interface} set channel {channel}",
        ]
        for cmd in cmds:
            result = await self._ssh.exec_sudo(cmd)
            if result.exit_code != 0:
                raise RuntimeError(f"Sniffer setup failed: {cmd}\n{result.stderr}")

    async def teardown(self) -> None:
        """停止抓包 + 恢复 managed 模式"""
        await self.stop_capture()
        for cmd in [
            f"ip link set {self.interface} down",
            f"iw dev {self.interface} set type managed",
            f"ip link set {self.interface} up",
        ]:
            await self._ssh.exec_sudo(cmd)

    async def start_capture(self, pcap_path: Path,
                            bpf_filter: str = "") -> None:
        """启动远程 tcpdump 后台抓包"""
        self._pcap_remote = f"/tmp/sniffer_{_timestamp()}.pcap"
        filter_arg = f"'{bpf_filter}'" if bpf_filter else ""
        result = await self._ssh.exec_sudo(
            f"tcpdump -i {self.interface} {filter_arg} "
            f"-w {self._pcap_remote} -U & echo $!"
        )
        self._capture_pid = result.stdout.strip()

    async def stop_capture(self) -> Path:
        """停止 tcpdump，拉回 pcap"""
        if self._capture_pid:
            await self._ssh.exec_sudo(f"kill {self._capture_pid}")
            self._capture_pid = None
        local = Path(f"/tmp/_sniffer_{_timestamp()}.pcap")
        await self._ssh.pull_file(self._pcap_remote, local)
        return local
```

### 3.4 Fixture (`tests/conftest.py`)

新增 `sniffer` fixture：

```python
@pytest.fixture(scope="function")
async def sniffer(conn_pool, config):
    device = SnifferDevice(
        conn_pool.ssh["sniffer"],
        config.sniffer.interface,
    )
    yield device
    await device.teardown()
```

### 3.5 配置模板 (`config/topology.yaml`)

新增 `sniffer` 段：

```yaml
sniffer:
  host: 192.168.100.28
  ssh_port: 22
  user: root
  password: ~
  interface: wlan1mon
```

## 4. 使用示例

```python
@pytest.mark.scenario("sta_association")
async def test_sta_auth_assoc_with_sniffer(ap_configured, sta, sniffer, test_log_dir):
    # Sniffer 在信道 6 开始抓包
    await sniffer.setup(channel=6)
    await sniffer.start_capture(test_log_dir / "air.pcap")

    # STA 注入 AUTH + ASSOC
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:01")
    await sta.associate(stas[0], BSSID, "JXX", SecurityParams(...))

    # 等待 AP 响应
    await asyncio.sleep(2)

    # 停止并获取 pcap
    pcap = await sniffer.stop_capture()

    # 独立验证：sniffer 的 pcap 中只有真正空口传输的帧
    assert pcap_has_auth_response(pcap, stas[0].mac)
```

## 5. 与 STA 抓包的区别

| | STA 抓包 (`sta.start_capture`) | Sniffer 抓包 (`sniffer.start_capture`) |
|---|---|---|
| 网卡模式 | 同 injection 接口 | 独立接口 |
| 自注入回环 | 会捕获 | 不会 |
| 帧可信度 | 低（含本地回环） | 高（仅空口真实帧） |
| 用途 | Injection 调试 | 空口协议验证 |

## 6. 依赖

无新增依赖。复用现有 paramiko (SSH)、tcpdump (远端抓包)、scapy (本地 pcap 分析)。
