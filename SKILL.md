# WLAN 自动化测试脚本开发规范

基于 [Andrej Karpathy 对 LLM 编码陷阱的观察](https://github.com/multica-ai/andrej-karpathy-skills)，
制定本仓库所有自动化测试脚本的开发规范。

---

## 原则 1：先想后写 (Think Before Coding)

**不假设。不隐藏困惑。呈现权衡。**

### 1.1 写代码前必须明确

- **声明假设**。如果测试依赖 AP 固件行为、RF 环境、特定信道 —— 写在文档/注释里。
  ```
  # [ASSUMPTION] AP 在 channel 6, 2.4GHz, WPA2-PSK 模式下运行
  # [ASSUMPTION] monitor 接口 wlan0mon 存在且支持注入
  ```
- **多个协议解释同时存在时，全部列出。** 802.11 规范有歧义处，不要默默选一个。
  例如：Auth 帧 seqnum 字段某些实现从 1 开始，某些从 0 开始。
- **该反对时反对。** 如果用户要求写一个违反 802.11 协议语义的测试，说明原因。
- **困惑时停下。** 不理解 fixture 作用或帧构造逻辑时，明确指出哪里不清楚，请求澄清。

### 1.2 反模式

```
❌ 用户说"加个测试"，直接写了个测试函数，没问：
   - 需要多大的 STA 数量？
   - 需要验证什么？（pcap？AP 日志？RSSI？）
   - 测试应该 pass 还是 fail？
✅ 先问澄清问题，确认后再写。
```

---

## 原则 2：简洁优先 (Simplicity First)

**只写解决问题的最少代码。不写推测性代码。**

### 2.1 WLAN 测试的具体规则

| 规则 | 说明 |
|------|------|
| 一个测试函数 = 一个场景 | 不要把 deauth flood 和 invalid rates 合并到一个函数 |
| 单次使用的代码不提取 | 如果只有 `test_truncated_frames.py` 用 `_build_control_short()`，就留在这个文件里 |
| 不写未要求的灵活性 | 不要给只用 802.11g 的测试加上 `--phy` 参数支持 |
| 不写不可能场景的错误处理 | Scapy 的 `sendp()` 外面包 `try/except RuntimeError` 是噪音 |
| 200 行能写成 50 行的，重写 | 参考 RUN/scapy 中 50-80 行的紧凑测试 |

### 2.2 反模式

```python
# ❌ 过度抽象 — 一个函数只被一个地方调用
def _build_mgmt_short(sta, bssid):
    """只用了一次但提取成了独立函数"""
    full = struct.pack(...) + ...
    return RadioTap() / Raw(load=full[:20])

# ❌ 未要求的灵活性
class TestBuilder:
    def __init__(self, mode="deauth", reason=1, spoof_ap=False, ...):
        """只用了 mode=deauth, reason=1，但设计了 5 个参数"""
        ...

# ✅ 简洁直接
def test_deauth_flood():
    frame = build_deauth_frame(sta, bssid, bssid, reason=1)
    # 直接构造，即时发送
```

### 2.3 酸测试

> 一个资深 WLAN 测试工程师会说这段代码过于复杂吗？ 如果是，简化它。

---

## 原则 3：精准变更 (Surgical Changes)

**只改必须改的。只清理你自己制造的混乱。**

### 3.1 编辑现有代码时

- **不要"改进"相邻代码、注释、格式。** 你没在改的帧构造器不需要顺便升级 docstring。
- **不要重构没坏的东西。** `wifi_mgmt_common.py` 的风格和 `src/wlan/frames.py` 的风格不同
  —— 两者都能用，新代码选一种，但不要翻修另一种。
- **匹配你正在编辑的文件风格。** `build_auth_frame()` 用了 `_dot11_header()` 模式，就沿用，
  不要换成 `build_probe_req()` 的风格。
- **发现无关的死代码，提出来但不要删。** `src/cli/parser.py` 可能没人用，标记它，不要直接删。

### 3.2 清理你自己的变更

- 你的变更导致的未使用 import/变量/函数 —— **必须清理**。
- 已存在的死代码 —— **不要删**，除非明确被要求。

### 3.3 测试标准

```
每一行改动都应该能追溯到用户的需求。
```

---

## 原则 4：目标驱动执行 (Goal-Driven Execution)

**定义成功标准。循环直到验证通过。**

### 4.1 任务转换

| 命令式（不推荐） | 目标式（推荐） |
|---|---|
| "加一个 deauth flood 测试" | "写 test_deauth_flood：发送 10 个 deauth 帧，验证 pcap 中包含全部 10 个" |
| "修 StaInjector.associate 的 bug" | "写一个能复现序列号 bug 的测试，然后修复它" |
| "把 test_sta_reassoc 迁移到 pytest" | "创建 test_reassoc.py，pytest 可执行，验证 ReassoReq 在 pcap 中，耗时 < 5s" |

### 4.2 多步任务模板

```
1. [步骤] → 验证: [检查项]
2. [步骤] → 验证: [检查项]
3. [步骤] → 验证: [检查项]
```

WLAN 实例：
```
1. 在 frames.py 添加 build_reassoc_req_frame()   → 验证: import 成功, 类型检查通过
2. 创建 tests/scenarios/sta_roaming/test_reassoc.py → 验证: pytest --collect-only 收集到
3. 用 codegraph callers 确认无破坏               → 验证: 调用者列表无意外变化
4. 运行测试                                       → 验证: 0 失败
```

### 4.3 原则

> Karpathy: "LLM 非常擅长循环直到达到特定目标……不要告诉它做什么，给它成功标准然后看它执行。"

---

## 规范生效的标志

| 现象 | 说明 |
|------|------|
| diff 只包含被要求的改动 | 没有对相邻帧构造器的"顺便改进" |
| 没有因过度复杂而重写 | 测试函数第一次就控制在 20-80 行 |
| 澄清问题在实现之前提出 | "这个测试应该期望 Status Code 18 还是 Deauth？"先问 |
| PR 干净、最小化 | 一个 PR = 一个场景，没有顺手重构 |

---

## 整合到 CLAUDE.md

本规范已合并到项目根目录 `CLAUDE.md`，对 Claude Code 和 Hermes Agent 均生效。

相关资源：
- [原始 Karpathy 推特](https://x.com/karpathy/status/2015883857489522876)
- [multica-ai/andrej-karpathy-skills](https://github.com/multica-ai/andrej-karpathy-skills)
