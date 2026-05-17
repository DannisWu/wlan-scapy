# WLAN AP 无线驱动测试平台

基于 pytest 的 Wi-Fi AP 无线驱动自动化测试平台。通过 SSH/Telnet 远程控制多台设备，支持 802.11 injection 模拟多 STA 和 scapy 802.3 有线流量生成。

## 架构

```
Test Runner (pytest)
    │
    ├── SSH ──► Wired PC       (scapy 802.3 流量生成)
    ├── SSH ──► WLAN STA       (802.11 injection, 多 STA 模拟)
    ├── SSH ──► WLAN Sniffer   (空口被动抓包, 可选)
    ├── Telnet ──► DUT AP      (私有 CLI 配置 / 状态查询)
    └── Serial ──► DUT AP      (异常日志监听, 可选)
```

> 所有角色不限制独立设备——可部署在同一台或不同机器上，只需在配置中指定各自的 `host`。

```
src/
├── connections/     SSH / Telnet / Serial 连接管理
├── transport/       FrameTransport 抽象 (Radio / Tunnel 预留)
├── devices/         APController / StaInjector / TrafficGenerator / SnifferDevice
├── wlan/            802.11 帧构建 + IE 构建 + 异常序列
├── traffic/         802.3 报文构建 (ARP/ICMP/DHCP/TCP/UDP/分片)
├── cli/             AP CLI 输出解析
└── utils/           配置加载 / PCAP 管理
```

## 快速开始

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

编辑 `config/topology.yaml`：

```yaml
wired_pc:
  host: 192.168.1.10
  ssh_port: 22
  user: root
  password: your_password
  interface: eth1

sta:
  host: 192.168.1.20
  ssh_port: 22
  user: root
  password: your_password
  transport:
    type: radio
    interface: wlp2s0

sniffer:                       # 可选角色，host 留空则不启用
  host: ""
  ssh_port: 22
  user: root
  password: ~
  interface: wlan1mon

ap:
  telnet:
    host: 192.168.1.1
    port: 23
  serial:
    enable: false
```

## 运行测试

```bash
# 全部测试 (需硬件)
pytest tests/ -v

# 仅单元测试 (无需硬件)
pytest tests/connections/ tests/wlan/ tests/traffic/ tests/cli/ tests/utils/ -v

# 按场景筛选
pytest tests/scenarios/sta_association/ -v     # STA 接入
pytest tests/scenarios/traffic_forwarding/ -v   # 报文转发
pytest tests/scenarios/multi_sta/ -v            # 多 STA 并发

# 按 Wi-Fi 标准
pytest -m "wifi_standard and 11ax" -v

# 环境验证
pytest tests/test_environment_verify.py -v

# 生成 HTML 报告
pytest tests/ --html=reports/report.html --self-contained-html
```

## 编写新测试

```python
import pytest
from src.devices.sta import SecurityParams

@pytest.mark.scenario("sta_association")
@pytest.mark.wifi_standard("11ax")
async def test_my_case(ap_configured, sta, test_log_dir):
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:01")
    result = await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff", "test-ax",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    assert result.status == 0
```

### 可用 Fixture

| Fixture | 说明 |
|---------|------|
| `ap` | AP 控制 (每次测试后自动检查 dmesg+串口异常) |
| `ap_configured` | 已配好 802.11ax 的 AP |
| `sta` | STA 注入控制 (最多 32 个虚拟 STA) |
| `wired_pc` | 有线侧 scapy 流量生成 |
| `sniffer` | 独立空口抓包 (未配置时自动跳过) |
| `test_log_dir` | 测试专用日志/pcap 目录 |

### 可用 Marker

```python
@pytest.mark.scenario("sta_association")
@pytest.mark.wifi_standard("11ax")
```

## 测试产出

每个测试自动在 `reports/<test_name>/` 下生成：

```
├── air.pcap              # 空口抓包
├── dmesg_before.txt      # 测试前内核日志
├── dmesg_after.txt       # 测试后内核日志
└── serial.log            # 串口监听日志
```

## 802.11 Injection 说明

Intel AX200/AX210 (iwlwifi 驱动) 的 monitor 模式仅支持 RX，不支持 TX packet injection。要进行 802.11 异常帧注入测试，需要支持 active monitor 的网卡：

| 芯片 | 接口 | 驱动 | 5GHz |
|------|------|------|------|
| MT7612U | USB | mt76x2u | ✅ |
| AR9271 | USB | ath9k_htc | ❌ (仅 2.4G) |
| RT5572 | USB | rt2800usb | ✅ |

正常 WiFi 连接测试（managed 模式 + wpa_supplicant）不受此限制。

## 常见问题

**连接失败？** 检查 `config/topology.yaml` 中 IP、端口、密码是否正确。

**串口异常误报？** 编辑 `src/connections/serial.py` 中的 `DEFAULT_ERROR_PATTERNS`。
