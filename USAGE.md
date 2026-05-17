# WLAN AP 无线驱动测试平台 — 使用指南

## 1. 配置拓扑

编辑 `config/topology.yaml`，填入实际设备信息：

```yaml
wired_pc:
  host: 10.0.0.10          # 有线 PC 的 IP
  ssh_port: 22
  user: root
  password: your_password  # 或配置 SSH key
  interface: eth1           # 连接 DUT AP 的网口名

sta:
  host: 10.0.0.20           # WLAN STA 的 IP
  ssh_port: 22
  user: root
  password: your_password
  transport:
    type: radio
    interface: wlp2s0        # AX200 网卡接口名

ap:
  telnet:
    host: 10.0.0.1           # DUT AP 的 IP
    port: 23
  serial:
    enable: true             # 启用串口异常监听
    mode: local              # local 或 comhub
    port: /dev/ttyUSB0
    baudrate: 115200
```

## 2. 环境准备

```bash
cd /home/wudan/workspace/wlan-scapy
source venv/bin/activate
```

## 3. 运行测试

### 运行全部测试

```bash
pytest tests/ -v
```

### 按场景运行

```bash
# 仅 STA 接入测试
pytest tests/scenarios/sta_association/ -v

# 仅报文转发测试
pytest tests/scenarios/traffic_forwarding/ -v

# 仅多 STA 并发测试
pytest tests/scenarios/multi_sta/ -v
```

### 按 Wi-Fi 标准筛选

```bash
pytest -m wifi_standard -v          # 所有标准
pytest -m "wifi_standard and 11ax" -v  # 仅 802.11ax
```

### 按正常/异常筛选

```bash
pytest tests/scenarios/sta_association/normal/ -v     # 正常流程
pytest tests/scenarios/sta_association/abnormal/ -v   # 异常流程
```

### 运行单个测试

```bash
pytest tests/scenarios/sta_association/normal/test_11ax.py::test_single_sta_assoc_11ax -v
```

## 4. 生成 HTML 报告

```bash
pytest tests/ --html=reports/report.html --self-contained-html
```

每个测试会在 `reports/<test_name>_<timestamp>/` 下自动产出：

```
reports/test_single_sta_assoc_11ax_20250101_120000/
├── air.pcap              # 空口抓包
├── dmesg_before.txt      # 测试前 dmesg
├── dmesg_after.txt       # 测试后 dmesg
└── serial.log            # 串口监听日志
```

## 5. 编写新测试

在对应场景目录下新建 `test_*.py` 文件，使用已有 fixture：

```python
import pytest
from src.devices.sta import SecurityParams

@pytest.mark.scenario("sta_association")
async def test_my_custom_case(ap_configured, sta, test_log_dir):
    stas = await sta.create_stas(1, base_mac="00:11:22:33:00:01")
    result = await sta.associate(
        stas[0], "ff:ff:ff:ff:ff:ff", "test-ax",
        SecurityParams(auth="WPA2", psk="test1234"),
    )
    assert result.status == 0
```

### 可用 Fixture

| Fixture | 类型 | 说明 |
|---------|------|------|
| `ap` | APController | 每次测试自动检查 dmesg+串口异常 |
| `ap_configured` | APController | 已配好 802.11ax 参数的 AP |
| `sta` | StaInjector | 注入控制，支持最多 32 个虚拟 STA |
| `wired_pc` | TrafficGenerator | 有线侧流量生成 |
| `test_log_dir` | Path | 测试专用的日志/pcap 目录 |

### 可用 Marker

```python
@pytest.mark.scenario("sta_association")   # 场景分类
@pytest.mark.wifi_standard("11ax")        # Wi-Fi 标准
```

## 6. 常见问题

**Q: 测试连接失败？**
检查 `config/topology.yaml` 中 IP、端口、密码是否正确，确保各设备 SSH/Telnet 可达。

**Q: STA 注入不工作？**
确认 AX200 支持 monitor mode：`iw list | grep monitor`。确保 `transport.interface` 配置正确。

**Q: 串口异常误报？**
编辑 `src/connections/serial.py` 中的 `DEFAULT_ERROR_PATTERNS`，调整匹配模式。

**Q: 只想运行不需要硬件的单元测试？**
```bash
pytest tests/connections/ tests/wlan/ tests/traffic/ tests/cli/ tests/utils/ -v
```
