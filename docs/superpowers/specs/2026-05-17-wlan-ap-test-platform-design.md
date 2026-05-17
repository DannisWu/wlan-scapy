# WLAN AP 设备无线驱动测试平台 — 设计文档

**日期**: 2026-05-17
**状态**: 已确认

## 1. 概述

### 1.1 目标

构建基于 pytest 的 Wi-Fi AP 设备无线驱动自动化测试平台，支持正常与异常场景下的 802.11 接入测试和 802.3 报文转发测试。

### 1.2 物理拓扑

```
┌──────────────────┐         ┌──────────────┐         ┌──────────────────────┐
│   Test Runner    │  SSH    │  Wired PC    │  Eth    │       DUT AP         │
│   (pytest)       │◄───────►│  (scapy)     │◄───────►│  (待测 AP 设备)       │
│                  │         │              │         │                      │
│  • 测试用例编排   │         │ • 802.3 流量  │         │  • Telnet CLI 控制   │
│  • 结果收集       │         │ • 有线侧仿真  │         │  • 串口异常监听       │
└──────────────────┘         └──────────────┘         └──────────┬───────────┘
                                                                 │ 802.11 WiFi
                                                                 │
                                                     ┌───────────▼───────────┐
                                           SSH       │  WLAN STA              │
                                         ◄──────────►│  (Intel AX200)         │
                                                     │                        │
                                                     │  • 802.11 Injection    │
                                                     │  • 多 STA 模拟 (32)    │
                                                     │  • 异常帧/异常交互     │
                                                     └────────────────────────┘
```

四台设备均为独立物理机，控制通道：

| 目标设备 | 连接方式 | 交互界面 | 用途 |
|---------|---------|---------|------|
| Wired PC | SSH | Linux Shell (Ubuntu) | scapy 发包/抓包 |
| WLAN STA | SSH | Linux Shell (Ubuntu 24.04) | 802.11 injection/monitor |
| DUT AP | Telnet | 私有 CLI | 配置、状态查询、日志 |
| DUT AP | 串口 (本地/ComHub) | 串口终端 | 被动监听异常 (oops/panic) |

### 1.3 关键约束

- **WLAN STA 硬件**: 1 块 Intel AX200，通过 monitor mode + injection 模拟最多 32 个虚拟 STA
- **Wi-Fi 标准覆盖**: 802.11a/b/g/n/ac/ax
- **DUT CLI**: 私有命令行界面，逐条命令执行，支持交互确认（如 reboot confirm）
- **串口接入**: 支持本地串口 (`/dev/ttyUSBx`) 和 ComHub 串口服务器 (Telnet) 两种模式
- **验证方式**: 以报文验证为主（pcap 检查），CLI/日志验证为辅
- **未来扩展**: 预留虚拟 AP + 自定义隧道传输方式

## 2. 整体分层架构

```
┌─────────────────────────────────────────────────────────┐
│                    测试层 (tests/)                       │
│  pytest test cases · fixtures · markers · parametrize   │
├─────────────────────────────────────────────────────────┤
│                    领域层 (src/wlan/ src/traffic/)       │
│  802.11帧构建(正常+畸形) · 协议交互序列 · 802.3报文构建   │
│  CLI输出解析器 · PCAP管理                                │
├─────────────────────────────────────────────────────────┤
│                    设备层 (src/devices/)                 │
│  APController · StaInjector · TrafficGenerator          │
├─────────────────────────────────────────────────────────┤
│                    传输层 (src/transport/)               │
│  RadioTransport · TunnelTransport (预留)                 │
├─────────────────────────────────────────────────────────┤
│                    连接层 (src/connections/)             │
│  SSH · Telnet · Serial · 连接池                          │
└─────────────────────────────────────────────────────────┘
```

**设计原则**:
- 连接层只负责字节传输，不关心上层语义
- 传输层隔离帧的物理收发方式，上层设备层不感知
- 设备层封装设备操作，暴露语义化方法
- 领域层提供纯数据构建，与设备无关，可独立单元测试
- 测试层只做编排：准备数据 → 下发执行 → 采集结果 → 断言

### 2.1 项目目录结构

```
wlan-scapy/
├── pyproject.toml
├── config/
│   ├── topology.yaml          # 设备IP、端口、凭据
│   └── ap_profiles/           # AP无线参数模板
├── src/
│   ├── connections/            # 连接层
│   │   ├── base.py
│   │   ├── ssh.py             # SSH (paramiko)
│   │   ├── telnet.py          # Telnet (telnetlib3)
│   │   ├── serial.py          # 串口 (pyserial / telnet)
│   │   └── pool.py            # 连接池
│   ├── transport/             # 传输层
│   │   ├── base.py            # FrameTransport 抽象
│   │   ├── radio.py           # RadioTransport (AX200 injection)
│   │   └── tunnel.py          # TunnelTransport (未来)
│   ├── devices/               # 设备层
│   │   ├── ap.py              # APController
│   │   ├── sta.py             # StaInjector
│   │   └── wired_pc.py        # TrafficGenerator
│   ├── wlan/                  # 领域层 - 802.11
│   │   ├── frames.py          # 帧模板
│   │   ├── ie.py              # IE构建器(正常+畸形)
│   │   ├── sequences.py       # Auth/Assoc/4-way-handshake序列
│   │   └── anomalies.py       # 异常交互模板
│   ├── traffic/               # 领域层 - 802.3
│   │   ├── l3.py              # ARP/ICMP/DHCP/NDP
│   │   ├── l4.py              # TCP/UDP
│   │   └── special.py         # 超长/分片/广播组播
│   ├── cli/                   # CLI解析
│   │   └── parser.py
│   └── utils/
│       ├── pcap.py            # PCAP管理
│       └── report.py          # 报告附件
├── tests/
│   ├── conftest.py            # 顶层fixture
│   └── scenarios/
│       ├── sta_association/   # 场景: STA接入
│       │   ├── conftest.py
│       │   ├── normal/        # 协议层: 正常流程
│       │   └── abnormal/      # 协议层: 异常流程
│       ├── traffic_forwarding/ # 场景: 报文转发
│       │   ├── conftest.py
│       │   ├── normal/
│       │   └── abnormal/
│       └── multi_sta/         # 场景: 多STA并发
│           └── normal/
└── reports/                   # 输出目录
```

## 3. 连接层

### 3.1 SSH 连接

```python
class SSHConnection:
    """Wired PC / WLAN STA 的 SSH 连接"""
    async def exec(self, cmd: str, timeout: float = 30) -> SSHResult: ...
    async def exec_sudo(self, cmd: str) -> SSHResult: ...
    async def push_file(self, local: Path, remote: str) -> None: ...
    async def pull_file(self, remote: str, local: Path) -> None: ...
```

### 3.2 Telnet 连接

```python
class TelnetConnection:
    """DUT AP CLI"""
    async def send_cmd(self, cmd: str, timeout: float = 30) -> TelnetResult: ...
    async def wait_for(self, pattern: str, timeout: float = 30) -> str: ...
    async def send_cmd_expect(self, cmd: str, expected: str, timeout: float = 30) -> bool: ...
```

### 3.3 串口连接

支持两种物理接入方式，统一行为接口：

```python
class SerialMode(Enum):
    LOCAL = "local"        # 本地串口 /dev/ttyUSBx
    COMHUB = "comhub"      # 串口服务器 (Telnet协议)

class SerialConnection:
    """被动监听 DUT AP 异常输出"""
    async def open(self, mode: SerialMode, **kwargs) -> None: ...
    async def start_monitor(self, log_file: Path) -> None: ...
    async def stop_monitor(self) -> str: ...
    async def check_errors(self, patterns: list[str] = None) -> list[str]: ...
```

内部根据 mode 选择不同的 reader 实现（pyserial vs telnet），上层不感知差异。

### 3.4 连接池

```python
class ConnectionPool:
    ssh_connections: dict[str, SSHConnection]   # key: "wired_pc", "sta"
    telnet_connection: TelnetConnection          # key: "ap"
    serial_connection: SerialConnection | None   # 可选
    
    async def connect_all(self) -> None: ...
    async def disconnect_all(self) -> None: ...
```

连接池在 `scope="session"` fixture 中初始化，全测试会话复用，避免重复建连。

## 4. 传输层

隔离 802.11 帧的物理收发方式，为未来虚拟 AP 隧道预留扩展点：

```python
class FrameTransport(ABC):
    """802.11帧传输抽象"""
    async def send(self, frame: bytes, channel: int, ...) -> None: ...
    async def recv(self, filter: str, timeout: float) -> list[bytes]: ...
    async def start_capture(self, pcap_path: str) -> None: ...
    async def stop_capture(self) -> str: ...

class RadioTransport(FrameTransport):
    """AX200 monitor mode + injection 实现"""

class TunnelTransport(FrameTransport):
    """未来：自定义隧道收发 802.11 帧"""
```

设备层通过依赖注入使用 `FrameTransport`，不感知底层传输方式。

## 5. 设备层

### 5.1 APController — DUT AP 控制

```python
class APController:
    """Telnet CLI + 串口监听"""
    
    # 无线配置
    async def set_radio(self, channel, mode, bandwidth) -> None: ...
    async def set_ssid(self, ssid, index=0) -> None: ...
    async def set_security(self, auth, encryption, psk=None) -> None: ...
    
    # 状态查询
    async def get_sta_list(self) -> list[StaInfo]: ...
    async def get_stats(self) -> dict: ...
    
    # dmesg 日志
    async def get_dmesg(self) -> str: ...
    async def clear_dmesg(self) -> None: ...
    async def check_dmesg(self, before, after, patterns=None) -> list[str]: ...
    
    # 串口监控
    async def start_monitoring(self, log_dir) -> None: ...
    async def stop_monitoring(self) -> tuple[str, list[str]]: ...
    
    # 控制
    async def reboot(self) -> None: ...
    async def factory_reset(self) -> None: ...
    async def clear_logs(self) -> None: ...
```

### 5.2 StaInjector — WLAN STA 注入控制

```python
class StaInjector:
    """802.11 帧注入 + 多 STA 管理"""
    
    def __init__(self, transport: FrameTransport, ssh: SSHConnection):
        self.transport = transport  # RadioTransport | TunnelTransport
        self.stas: list[StaInstance] = []
    
    # STA 生命周期
    async def create_stas(self, count, base_mac) -> list[StaInstance]: ...
    async def destroy_stas(self) -> None: ...
    
    # 单 STA 操作
    async def associate(self, sta, bssid, ssid, security) -> AssocResult: ...
    async def send_auth(self, sta, bssid, **params) -> None: ...
    async def send_assoc(self, sta, bssid, **params) -> None: ...
    async def send_frame(self, sta, frame: bytes) -> None: ...
    async def send_sequence(self, sta, sequence: FrameSequence) -> None: ...
    
    # 批量操作
    async def associate_all(self, bssid, ssid) -> list[AssocResult]: ...
    
    # 抓包
    async def start_capture(self, pcap_path, filter="") -> None: ...
    async def stop_capture(self) -> str: ...
```

### 5.3 TrafficGenerator — 有线 PC 流量生成

```python
class TrafficGenerator:
    """基于 scapy 的 802.3 报文收发"""
    
    # L3
    async def send_arp(self, op, src_ip, dst_ip, count=1): ...
    async def send_icmp(self, src_ip, dst_ip, icmp_type=8, count=1, size=64): ...
    async def send_dhcp(self, msg_type, **params): ...
    
    # L4
    async def send_tcp(self, src_ip, dst_ip, sport, dport, flags="S", payload=b""): ...
    async def send_udp(self, src_ip, dst_ip, sport, dport, payload=b""): ...
    
    # 广播/组播
    async def send_broadcast(self, packet, count=1): ...
    async def send_multicast(self, group, packet, count=1): ...
    
    # 特殊报文
    async def send_jumbo(self, size=9000, **params): ...
    async def send_fragmented(self, payload, frag_size=1480): ...
    
    # 抓包
    async def start_capture(self, interface, filter, pcap_path) -> None: ...
    async def stop_capture(self) -> str: ...
```

### 5.4 StaInstance — 虚拟 STA 实体

```python
@dataclass
class StaInstance:
    mac: str
    capabilities: int
    supported_rates: list[int]
    ht_cap: HTCapabilities | None
    vht_cap: VHTCapabilities | None
    he_cap: HECapabilities | None
    state: StaState             # DISCONNECTED / AUTH / ASSOCIATED / 4WAY
    rsn: RSNAuthParams | None
```

## 6. 领域层

### 6.1 802.11 帧构建 (`src/wlan/`)

**帧模板 (frames.py)**:
```python
def build_auth_frame(sender, receiver, bssid, seq_num, algo=0, status=0) -> bytes: ...
def build_assoc_req_frame(sender, receiver, bssid, ssid, capabilities, rates, ies=None, seq_num=0) -> bytes: ...
def build_probe_req_frame(...) -> bytes: ...
def build_deauth_frame(...) -> bytes: ...
def build_disassoc_frame(...) -> bytes: ...
def build_data_frame(..., encrypt=False, key=None) -> bytes: ...
```

**IE 构建器 (ie.py)**:
```python
# 正常 IE
def ssid_ie(ssid) -> IE: ...
def supported_rates_ie(rates) -> IE: ...
def ht_capabilities_ie(caps) -> IE: ...
def vht_capabilities_ie(caps) -> IE: ...
def he_capabilities_ie(caps) -> IE: ...
def rsn_ie(params) -> IE: ...

# 畸形 IE
def oversized_ie(id, size) -> IE: ...
def truncated_ie(id, actual_len) -> IE: ...
def vendor_malformed_ie(oui, data) -> IE: ...
```

**异常交互模板 (anomalies.py)**:
```python
@dataclass
class FrameSequence:
    steps: list[FrameStep]

@dataclass
class FrameStep:
    frame: bytes
    delay: float = 0
    expect: str = None

# 预定义异常序列
def assoc_without_auth(...) -> FrameSequence: ...
def repeated_auth(...) -> FrameSequence: ...
def deauth_during_4way(...) -> FrameSequence: ...
def wrong_seq_num(...) -> FrameSequence: ...
```

### 6.2 802.3 流量构建 (`src/traffic/`)

```python
# l3.py
def build_arp_request(src_mac, src_ip, dst_ip) -> bytes: ...
def build_arp_reply(src_mac, src_ip, dst_mac, dst_ip) -> bytes: ...
def build_icmp_echo(src_ip, dst_ip, payload_size=56) -> bytes: ...
def build_dhcp_discover(src_mac, ...) -> bytes: ...
def build_dhcp_request(src_mac, requested_ip, ...) -> bytes: ...
def build_nd_solicit(src_mac, src_ip6, target_ip6) -> bytes: ...

# l4.py
def build_tcp_syn(src_ip, dst_ip, sport, dport, ...) -> bytes: ...
def build_udp(src_ip, dst_ip, sport, dport, payload) -> bytes: ...

# special.py
def build_jumbo_packet(size=9000, **base_params) -> bytes: ...
def build_ipv4_fragments(payload, frag_size=1480) -> list[bytes]: ...
def build_ipv6_fragments(payload, frag_size=1280) -> list[bytes]: ...
def build_multicast_ipv4(group, payload) -> bytes: ...
def build_multicast_ipv6(group, payload) -> bytes: ...
```

### 6.3 CLI 解析 (`src/cli/parser.py`)

```python
class CLIParser:
    def parse_table(self, text, columns) -> list[dict]: ...
    def parse_sta_list(self, text) -> list[StaInfo]: ...
    def parse_stats(self, text, counter_type) -> dict: ...
    def wait_for_pattern(self, text, pattern) -> bool: ...
    def extract_value(self, text, key) -> str | None: ...
```

### 6.4 PCAP 管理 (`src/utils/pcap.py`)

```python
class PCAPManager:
    async def start(self, label, filter="") -> None: ...
    async def stop(self) -> str: ...
    def check_packets(self, pcap_path, condition) -> list: ...
    def verify_sequence(self, pcap_path, sequence) -> bool: ...
```

## 7. 测试层

### 7.1 Fixture 层级

```
tests/conftest.py (顶层)
  session:  config              ← 加载 topology.yaml
  session:  conn_pool           ← 建立全部连接
  function: test_log_dir        ← 测试日志/pcap 目录
  function: ap                  ← APController (含串口+dmesg检查)
  function: sta                 ← StaInjector (含 transport)
  function: wired_pc            ← TrafficGenerator
```

### 7.2 AP Fixture teardown 自动化检查

每个测试结束后自动执行：

1. 停止串口监听，检查异常行
2. 采集 dmesg after，与 dmesg before 对比，检查新增异常
3. 保存 `serial.log`、`dmesg_before.txt`、`dmesg_after.txt` 到测试目录
4. 断言无串口异常、无 dmesg 异常

```python
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
    assert not serial_errors, f"AP serial: {serial_errors}"
    assert not dmesg_errors, f"AP dmesg: {dmesg_errors}"
```

### 7.3 测试目录组织

测试用例按三级维度组织：场景 → 协议层 → Wi-Fi 标准

```
tests/scenarios/
├── sta_association/          # 场景: STA接入
│   ├── normal/               # 协议层: 正常流程
│   │   ├── test_11n.py       # Wi-Fi标准维度
│   │   ├── test_11ac.py
│   │   └── test_11ax.py
│   └── abnormal/             # 协议层: 异常流程
│       ├── test_malformed_ie.py
│       ├── test_protocol_violation.py
│       └── test_security_flaw.py
├── traffic_forwarding/       # 场景: 报文转发
│   ├── normal/
│   │   ├── test_l3_unicast.py
│   │   ├── test_l3_broadcast.py
│   │   ├── test_l3_multicast.py
│   │   └── test_l4_tcp_udp.py
│   └── abnormal/
│       ├── test_jumbo.py
│       └── test_fragmentation.py
└── multi_sta/                # 场景: 多STA并发
    └── normal/
        └── test_32sta.py
```

### 7.4 典型测试用例

```python
@pytest.mark.wifi_standard("11ax")
@pytest.mark.scenario("sta_association")
async def test_normal_assoc_11ax(ap_configured, sta, test_log_dir):
    """正常 802.11ax STA 接入流程"""
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:00")
    await sta.start_capture(test_log_dir / "air.pcap")
    
    result = await sta.associate(stas[0], ap_configured.bssid,
                                 ap_configured.ssid,
                                 SecurityParams(auth="WPA2", psk="test1234"))
    
    assert result.status == 0
    sta_list = await ap.get_sta_list()
    assert stas[0].mac in [s.mac for s in sta_list]
    await sta.stop_capture()
    assert pcap_has_4way_handshake(test_log_dir / "air.pcap", stas[0].mac)
```

### 7.5 报告

- pytest-html 生成标准 HTML 报告
- 每个测试用例产出的 `serial.log`、`dmesg_*.txt`、`*.pcap` 作为报告附件
- 测试失败时异常日志信息直接展示在断言消息中

## 8. 配置文件格式

```yaml
# config/topology.yaml
test_runner:
  report_dir: ./reports

wired_pc:
  host: 192.168.1.10
  ssh_port: 22
  user: root
  interface: eth1

sta:
  host: 192.168.1.20
  ssh_port: 22
  user: root
  transport:
    type: radio            # "radio" | "tunnel" (预留)
    interface: wlp2s0

ap:
  telnet:
    host: 192.168.1.1
    port: 23
  serial:
    mode: local             # "local" | "comhub"
    port: /dev/ttyUSB0
    baudrate: 115200
    enable: true
```

## 9. 依赖

- Python ≥ 3.10
- scapy (802.11/802.3 帧构建)
- paramiko (SSH)
- telnetlib3 (Telnet)
- pyserial (本地串口)
- pytest + pytest-asyncio + pytest-html
- PyYAML
