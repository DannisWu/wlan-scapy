#$language = "Python"
#$interface = "1.0"
"""
==========================================================================
RG-AC AP Configuration Stress Test (拷机脚本)
SecureCRT Python Script — RGOS 11.9(4)B1 / 11.9(6)B9

功能: 在 RG-AC 无线控制器上对目标 AP 进行配置拷机，遍历 ap-config 模式下
      所有配置命令，穷举参数组合，验证 AC 配置下发的稳定性。

用法: SecureCRT → Script → Run → 选择本脚本
      或: SecureCRT 命令行: crt.ScriptingHost.Run("ap_config_stress_test.py")

作者: WLAN Automation Test Engineer
日期: 2026-06-24
==========================================================================
"""

import os
import time
import re
from datetime import datetime
from typing import Optional

# ===========================================================================
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                   用户可配置变量 (USER CONFIGURABLE)                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# ===========================================================================

# --- AP 基本信息 ---
TARGET_AP_NAME = "stress-test-ap"      # 目标 AP 名称 (ap-config 下的名称)
TARGET_AP_MAC  = "00:00:00:00:00:01"  # 目标 AP MAC (可选，留空则跳过 MAC 绑定)
AP_LOCATION    = "lab-3f-cabinet-A"    # AP 位置描述

# --- 射频配置 ---
NUM_RADIOS     = 2                     # AP 射频数量: 1 (仅 2.4G) 或 2 (双频)
RADIO_1_TYPE   = "802.11b"             # Radio 1 频段: 802.11b (2.4G)
RADIO_2_TYPE   = "802.11a"             # Radio 2 频段: 802.11a (5G), 仅 NUM_RADIOS>=2 时生效

# 各射频支持的信道列表 (根据国家码 CN)
CHANNELS_2G = [1, 6, 11, 13]          # 2.4G 测试信道
CHANNELS_5G = [36, 40, 44, 48, 149, 153, 157, 161, 165]  # 5G 测试信道

# --- WLAN 配置 ---
NUM_WLANS      = 4                     # 测试 WLAN 数量 (1-16)
WLAN_START_ID  = 1                     # 起始 WLAN ID
WLAN_VLAN_BASE = 100                   # WLAN VLAN 起始值 (WLAN1=VLAN100, WLAN2=VLAN101...)

# --- AC 连接信息 ---
AC_PRIMARY_IP   = "192.168.1.1"        # 主用 AC IP
AC_PRIMARY_NAME = "AC-Primary"         # 主用 AC 名称
AC_SECONDARY_IP = "192.168.1.2"        # 备用 AC IP (可选)
AC_SECONDARY_NAME = "AC-Secondary"     # 备用 AC 名称

# --- 测试范围控制 ---
TEST_MODE = "full"                     # "full"=完整测试, "basic"=基础测试, "radio"=仅射频, "security"=仅安全
SKIP_DESTRUCTIVE = True                # True=跳过可能断连的命令(reload/reset/factory-reset等)
SKIP_VIRTUAL_AP  = True                # True=跳过AP虚拟化配置
SKIP_ERPS       = True                 # True=跳过ERPS环网配置
SKIP_IP_CONFIG  = True                 # True=跳过AP自身IP配置(可能导致离线)

# --- 执行控制 ---
CMD_DELAY       = 0.3                  # 每条命令间延迟(秒)
PROMPT_TIMEOUT  = 15                   # 等待 CLI 提示符超时(秒)
MAX_RETRIES     = 2                    # 命令失败后最大重试次数
LOG_FILE        = ""                   # 日志文件路径 (留空则自动生成于脚本同目录)
VERBOSE         = True                 # True=输出详细日志到 SecureCRT 窗口

# ===========================================================================
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                    SecureCRT 辅助函数                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# ===========================================================================

def get_crt():
    """获取 SecureCRT crt 对象 (兼容 SecureCRT 各版本)."""
    try:
        return crt  # SecureCRT 内建全局对象
    except NameError:
        try:
            # SecureCRT 7.x+ Scripting API
            import Scripting
            return Scripting.CRT
        except ImportError:
            raise RuntimeError(
                "本脚本必须在 SecureCRT 中运行。\n"
                "请通过: Script → Run → 选择本脚本 来执行。"
            )

def safe_send(cmd, add_newline=True):
    """发送命令到 SecureCRT 当前会话."""
    if add_newline:
        crt.Screen.Send(cmd + "\r\n")
    else:
        crt.Screen.Send(cmd)

def safe_wait(strings, timeout=None):
    """等待指定字符串出现 (支持多字符串)."""
    if timeout is None:
        timeout = PROMPT_TIMEOUT
    if isinstance(strings, str):
        strings = [strings]
    return crt.Screen.WaitForStrings(*strings, timeout=timeout)

def send_and_wait(cmd, expect=None, timeout=None):
    """发送命令并等待 CLI 提示符返回."""
    safe_send(cmd)
    if timeout is None:
        timeout = PROMPT_TIMEOUT
    if expect is None:
        # 匹配常见的 RGOS 提示符模式
        result = crt.Screen.WaitForStrings(
            ")#",   # config 模式: Ruijie(config)#, Ruijie(config-ap)# 等
            ">",     # exec 模式: Ruijie>
            "Error:",
            "Invalid",
            "%",
            timeout=timeout
        )
    else:
        result = safe_wait(expect, timeout)
    return result

def get_prompt():
    """读取当前行的 CLI 提示符."""
    row = crt.Screen.CurrentRow
    line = crt.Screen.Get(row, 1, row, crt.Screen.Columns)
    return line.strip()

def log(msg, level="INFO"):
    """输出日志到文件和控制台."""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    formatted = f"[{timestamp}] [{level:5s}] {msg}"
    
    # 写入日志文件
    if LOG_FILE:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted + "\n")
    
    # 输出到 SecureCRT 窗口
    if VERBOSE or level in ("ERROR", "WARN", "PASS", "FAIL"):
        crt.Screen.Send(f"\r\n{formatted}\r\n")

def log_pass(cmd):
    """记录通过的配置命令."""
    log(f"PASS | {cmd}", "PASS")

def log_fail(cmd, reason=""):
    """记录失败的配置命令."""
    log(f"FAIL | {cmd} | {reason}", "FAIL")

def log_skip(cmd, reason=""):
    """记录跳过的配置命令."""
    log(f"SKIP | {cmd} | {reason}", "SKIP")

def log_error(cmd, error):
    """记录错误."""
    log(f"ERROR | {cmd} | {error}", "ERROR")

# ===========================================================================
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                    命令发送与验证引擎                                    ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# ===========================================================================

class CommandResult:
    """命令执行结果."""
    def __init__(self, cmd, success, output="", error=""):
        self.cmd = cmd
        self.success = success
        self.output = output
        self.error = error

def execute_cmd(cmd, expect_ok=True, verify_no="", retries=MAX_RETRIES):
    """
    执行一条 CLI 命令并返回结果.
    
    Args:
        cmd:        要执行的命令字符串
        expect_ok:  True=期望成功, False=期望失败(如测试非法参数)
        verify_no:  如果指定，执行 no 形式的反向命令验证(如 "no ap-name ...")
        retries:    最大重试次数
    
    Returns:
        CommandResult 对象
    """
    for attempt in range(retries):
        # 发送命令
        safe_send(cmd)
        crt.Sleep(int(CMD_DELAY * 1000))
        
        # 读取屏幕输出 (捕获最近几行)
        row = crt.Screen.CurrentRow
        output_lines = []
        for r in range(max(1, row - 10), row + 1):
            line = crt.Screen.Get(r, 1, r, crt.Screen.Columns)
            if line.strip():
                output_lines.append(line.strip())
        output = "\n".join(output_lines[-5:])  # 最近5行
        
        # 检查错误关键字
        has_error = any(kw in output.lower() for kw in [
            "error:", "invalid", "incomplete", "ambiguous",
            "% unknown", "% invalid", "% incomplete"
        ])
        
        if expect_ok and not has_error:
            if verify_no:
                # 执行 no 命令验证
                safe_send(verify_no)
                crt.Sleep(int(CMD_DELAY * 1000) * 2)
            log_pass(cmd)
            return CommandResult(cmd, True, output)
        
        elif not expect_ok and has_error:
            # 期望失败且确实失败了 → 符合预期
            log_pass(f"{cmd} (expected failure)")
            return CommandResult(cmd, True, output, "expected failure")
        
        elif not expect_ok and not has_error:
            # 期望失败但命令却成功了 → 异常
            log_fail(cmd, "Expected failure but command succeeded")
            # 尝试回退
            if verify_no:
                safe_send(verify_no)
            return CommandResult(cmd, False, output, "unexpected success")
        
        else:
            # 命令失败
            if attempt < retries - 1:
                log(f"RETRY {attempt+1}/{retries} | {cmd}", "WARN")
                crt.Sleep(2000)  # 等待2秒后重试
            else:
                log_fail(cmd, output[:100])
                return CommandResult(cmd, False, output, output[:100])
    
    return CommandResult(cmd, False, "", "max retries exceeded")

# ===========================================================================
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                    测试套件: 命令定义与参数穷举                           ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# ===========================================================================

class TestSuite:
    """命令测试套件基类."""
    
    def __init__(self, name):
        self.name = name
        self.results = []
        self.pass_count = 0
        self.fail_count = 0
        self.skip_count = 0
    
    def run_cmd(self, cmd, expect_ok=True, verify_no="", skip=False, skip_reason=""):
        """执行命令并记录结果."""
        if skip:
            log_skip(cmd, skip_reason)
            self.skip_count += 1
            return CommandResult(cmd, False, skip_reason, "skipped")
        
        result = execute_cmd(cmd, expect_ok, verify_no)
        self.results.append(result)
        if result.success:
            self.pass_count += 1
        else:
            self.fail_count += 1
        return result
    
    def summary(self):
        total = self.pass_count + self.fail_count + self.skip_count
        return (f"\n{'='*60}\n"
                f"Suite: {self.name}\n"
                f"  PASS: {self.pass_count}  FAIL: {self.fail_count}  SKIP: {self.skip_count}  TOTAL: {total}\n"
                f"{'='*60}")


class APConfigStressTest:
    """AP 配置拷机主类."""
    
    def __init__(self):
        self.suites = []
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
    
    def enter_ap_config(self):
        """进入 ap-config 配置模式."""
        safe_send(f"config terminal")
        crt.Sleep(500)
        safe_send(f"ap-config {TARGET_AP_NAME}")
        crt.Sleep(500)
        log(f"Entered ap-config mode for AP: {TARGET_AP_NAME}")
    
    def exit_ap_config(self):
        """退出 ap-config 配置模式."""
        safe_send("end")
        crt.Sleep(300)
    
    # =======================================================================
    # Suite 1: AP 身份与基础配置
    # =======================================================================
    
    def suite_ap_identity(self):
        """AP 名称/MAC/凭据/统计定时器."""
        suite = TestSuite("1. AP Identity & Basic Config")
        self.enter_ap_config()
        
        # --- ap-name: AP 名称 ---
        log("\n>> 1.1 ap-name: AP 名称配置")
        suite.run_cmd(f"ap-name {TARGET_AP_NAME}")
        suite.run_cmd(f"ap-name AP-Stress-01")
        suite.run_cmd(f"ap-name AP-Stress-Max-Length-Name-0123456789012345678901234567890123456789")  # 63字符边界
        suite.run_cmd(f"ap-name AP-With-Hyphens", verify_no=f"no ap-name")
        suite.run_cmd(f"ap-name {TARGET_AP_NAME}")  # 恢复
        
        # --- ap-mac: MAC 地址绑定 ---
        if TARGET_AP_MAC and TARGET_AP_MAC != "00:00:00:00:00:01":
            log("\n>> 1.2 ap-mac: MAC 地址绑定")
            suite.run_cmd(f"ap-mac {TARGET_AP_MAC}")
            suite.run_cmd(f"ap-mac 00:1a:a9:00:00:01")
            suite.run_cmd(f"ap-mac ff:ff:ff:ff:ff:ff", expect_ok=False)  # 广播MAC应拒绝
            suite.run_cmd(f"ap-mac {TARGET_AP_MAC}")  # 恢复
        
        # --- credential: AP Telnet 凭据 ---
        log("\n>> 1.3 credential: AP Telnet 凭据")
        suite.run_cmd(f"credential admin admin123")
        suite.run_cmd(f"credential ruijie Ruijie@2024")
        suite.run_cmd(f"credential testuser Test@Pass123")
        suite.run_cmd(f"credential admin admin123")  # 恢复
        
        # --- statistics-timer: 统计上报间隔 ---
        log("\n>> 1.4 statistics-timer: 统计上报间隔")
        suite.run_cmd(f"statistics-timer 30")        # 默认
        suite.run_cmd(f"statistics-timer 60")        # 1分钟
        suite.run_cmd(f"statistics-timer 120")        # 2分钟
        suite.run_cmd(f"statistics-timer 10")         # 最小边界
        suite.run_cmd(f"statistics-timer 3600")       # 最大边界(1小时)
        suite.run_cmd(f"statistics-timer 0", expect_ok=False)  # 0应拒绝
        suite.run_cmd(f"statistics-timer 30", verify_no=f"no statistics-timer")
        
        # --- logging: 系统日志 ---
        log("\n>> 1.5 logging: AP 系统日志")
        suite.run_cmd(f"logging on")
        suite.run_cmd(f"logging server 192.168.1.100")
        suite.run_cmd(f"logging server 192.168.1.100 udp-port 514")
        suite.run_cmd(f"logging server 10.10.10.1 udp-port 10514")
        suite.run_cmd(f"logging server 192.168.1.100", verify_no=f"no logging server 192.168.1.100")
        suite.run_cmd(f"logging on", verify_no=f"no logging on")
        
        # --- location: AP 位置 ---
        log("\n>> 1.6 location: AP 位置信息")
        suite.run_cmd(f"location {AP_LOCATION}")
        suite.run_cmd(f"location lab-1f-server-room-rack-A3")
        suite.run_cmd(f"location {AP_LOCATION}")  # 恢复
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 2: AP 管理与重启 (慎用)
    # =======================================================================
    
    def suite_ap_admin(self):
        """AP 重启/复位/恢复出厂."""
        suite = TestSuite("2. AP Administration (重启/复位)")
        self.enter_ap_config()
        
        # --- reload: 定时重启 (仅配置, 不实际触发) ---
        log("\n>> 2.1 reload: AP 定时重启")
        if SKIP_DESTRUCTIVE:
            suite.run_cmd(f"reload at 03:00", skip=True, skip_reason="SKIP_DESTRUCTIVE=True")
            suite.run_cmd(f"reload at 23:59", skip=True, skip_reason="SKIP_DESTRUCTIVE=True")
        else:
            suite.run_cmd(f"reload at 03:00")
            suite.run_cmd(f"reload at 23:59")
            suite.run_cmd(f"reload at 12:00", verify_no=f"no reload")
        
        # --- factory-reset / reset 命令跳过 ---
        log("\n>> 2.2 reset/factory-reset: 跳过 (破坏性命令)")
        suite.run_cmd(f"factory-reset {TARGET_AP_NAME}", skip=True, skip_reason="破坏性命令")
        suite.run_cmd(f"reset single {TARGET_AP_NAME}", skip=True, skip_reason="破坏性命令")
        suite.run_cmd(f"reset all", skip=True, skip_reason="破坏性命令")
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 3: AP 优先级与 AC 冗余
    # =======================================================================
    
    def suite_ap_priority_backup(self):
        """AP 优先级 / 主备 AC / 热备."""
        suite = TestSuite("3. AP Priority & AC Redundancy")
        self.enter_ap_config()
        
        # --- ap-priority: AP 优先级功能 ---
        log("\n>> 3.1 ap-priority: AP 优先级开关")
        suite.run_cmd(f"ap-priority enable")
        suite.run_cmd(f"ap-priority disable")
        suite.run_cmd(f"ap-priority enable")
        
        # --- priority: 优先级值 ---
        log("\n>> 3.2 priority: AP 优先级值")
        suite.run_cmd(f"priority 0")   # 最低
        suite.run_cmd(f"priority 4")   # 中等
        suite.run_cmd(f"priority 7")   # 最高
        suite.run_cmd(f"priority 10", expect_ok=False)  # 超出范围
        suite.run_cmd(f"priority 4")
        
        # --- primary-base / secondary-base / tertiary-base: 主备AC ---
        log("\n>> 3.3 primary/secondary/tertiary-base: 主备 AC 地址")
        suite.run_cmd(f"primary-base {AC_PRIMARY_NAME} {AC_PRIMARY_IP}")
        suite.run_cmd(f"primary-base AC-Master-02 192.168.1.10")
        suite.run_cmd(f"primary-base {AC_PRIMARY_NAME} {AC_PRIMARY_IP}")  # 恢复
        
        if AC_SECONDARY_IP:
            suite.run_cmd(f"secondary-base {AC_SECONDARY_NAME} {AC_SECONDARY_IP}")
            suite.run_cmd(f"secondary-base {AC_SECONDARY_NAME} {AC_SECONDARY_IP} switch-back")
            suite.run_cmd(f"secondary-base AC-Backup-02 192.168.1.20 switch-back")
            suite.run_cmd(f"secondary-base {AC_SECONDARY_NAME} {AC_SECONDARY_IP}")  # 恢复
        
        suite.run_cmd(f"tertiary-base AC-Backup3 192.168.1.30")
        suite.run_cmd(f"tertiary-base AC-Backup3 192.168.1.30 switch-back")
        suite.run_cmd(f"tertiary-base AC-Backup3-New 192.168.1.31", 
                      verify_no=f"no tertiary-base")
        
        # --- backup-controller: AC 热备 ---
        log("\n>> 3.4 backup-controller: AC 热备主备控制器")
        suite.run_cmd(f"backup-controller-primary {AC_PRIMARY_NAME} {AC_PRIMARY_IP}")
        if AC_SECONDARY_IP:
            suite.run_cmd(f"backup-controller-secondary {AC_SECONDARY_NAME} {AC_SECONDARY_IP}")
            suite.run_cmd(f"backup-controller-secondary {AC_SECONDARY_NAME} {AC_SECONDARY_IP} switch-back")
        
        # --- ap-backup-group: AP 备份组 ---
        log("\n>> 3.5 ap-backup-group: AP 备份组")
        suite.run_cmd(f"ap-backup-group backup-group-1")
        suite.run_cmd(f"ap-backup-group backup-group-1 master")
        suite.run_cmd(f"ap-backup-group backup-group-2")  # 更换组
        suite.run_cmd(f"no ap-backup-group")
        
        # --- ap-priority disable 恢复 ---
        suite.run_cmd(f"ap-priority disable")
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 4: 射频参数 (per-Radio 穷举)
    # =======================================================================
    
    def suite_radio_params(self):
        """信道/功率/带宽/天线/GI/MCS 等射频参数穷举."""
        suite = TestSuite("4. Radio Parameters (射频参数)")
        
        for radio_id in range(1, NUM_RADIOS + 1):
            radio_type = RADIO_1_TYPE if radio_id == 1 else RADIO_2_TYPE
            band = "2.4G" if radio_type == "802.11b" else "5G"
            channels = CHANNELS_2G if band == "2.4G" else CHANNELS_5G
            
            log(f"\n{'='*50}")
            log(f">> 4.{radio_id} Radio {radio_id} ({band}) 射频参数穷举")
            log(f"{'='*50}")
            
            self.enter_ap_config()
            
            # --- channel: 信道 (穷举所有合法信道) ---
            log(f"\n>> 4.{radio_id}.1 channel: 信道穷举")
            suite.run_cmd(f"channel auto radio {radio_id}")   # 自动信道
            for ch in channels:
                suite.run_cmd(f"channel {ch} radio {radio_id}")
            suite.run_cmd(f"channel 14 radio {radio_id}", expect_ok=False)  # CN 禁止信道14
            suite.run_cmd(f"channel auto radio {radio_id}")    # 恢复自动
            
            # --- power local: 发射功率 (穷举关键值) ---
            log(f"\n>> 4.{radio_id}.2 power local: 功率穷举")
            power_values = [1, 10, 25, 50, 75, 100]  # 百分比
            for pct in power_values:
                suite.run_cmd(f"power local {pct} radio {radio_id}")
            suite.run_cmd(f"power local 0 radio {radio_id}", expect_ok=False)   # 0 非法
            suite.run_cmd(f"power local 101 radio {radio_id}", expect_ok=False) # 101 超出
            suite.run_cmd(f"power local 100 radio {radio_id}")  # 恢复最大
            
            # --- chan-width: 信道带宽 ---
            log(f"\n>> 4.{radio_id}.3 chan-width: 带宽穷举")
            if band == "2.4G":
                for width in [20, 40]:
                    suite.run_cmd(f"chan-width {width} radio {radio_id}")
            else:  # 5G
                for width in [20, 40, 80]:
                    suite.run_cmd(f"chan-width {width} radio {radio_id}")
                suite.run_cmd(f"chan-width 160 radio {radio_id}")  # 160MHz
            suite.run_cmd(f"chan-width 10 radio {radio_id}", expect_ok=False)  # 非法宽度
            
            # --- radio-type: 射频类型 ---
            log(f"\n>> 4.{radio_id}.4 radio-type: 频段类型")
            suite.run_cmd(f"radio-type {radio_id} {radio_type}")
            # 不交叉测试(2.4G不能设为802.11a)
            
            # --- antenna: 天线配置 ---
            log(f"\n>> 4.{radio_id}.5 antenna: 天线配置")
            suite.run_cmd(f"antenna transmit 1 radio {radio_id}")   # 单天线
            suite.run_cmd(f"antenna transmit 3 radio {radio_id}")   # 双天线(bit0+bit1)
            suite.run_cmd(f"antenna transmit 7 radio {radio_id}")   # 三天线
            suite.run_cmd(f"antenna transmit 15 radio {radio_id}")  # 四天线
            suite.run_cmd(f"antenna receive 3 radio {radio_id}")
            suite.run_cmd(f"antenna receive 7 radio {radio_id}")
            suite.run_cmd(f"antenna type omnidirection")   # 全向
            suite.run_cmd(f"antenna type direction")        # 定向
            suite.run_cmd(f"antenna type omnidirection")    # 恢复
            
            # --- beacon: Beacon 帧参数 ---
            log(f"\n>> 4.{radio_id}.6 beacon: Beacon 帧参数")
            suite.run_cmd(f"beacon period 100 radio {radio_id}")     # 默认
            suite.run_cmd(f"beacon period 20 radio {radio_id}")      # 最小值
            suite.run_cmd(f"beacon period 500 radio {radio_id}")     # 中间值
            suite.run_cmd(f"beacon period 1000 radio {radio_id}")    # 最大值
            suite.run_cmd(f"beacon period 10 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"beacon period 100 radio {radio_id}")     # 恢复
            
            # beacon dtim-period
            suite.run_cmd(f"beacon dtim-period 1 radio {radio_id}")   # 默认
            suite.run_cmd(f"beacon dtim-period 3 radio {radio_id}")   # 常见
            suite.run_cmd(f"beacon dtim-period 5 radio {radio_id}")
            suite.run_cmd(f"beacon dtim-period 255 radio {radio_id}") # 最大值
            suite.run_cmd(f"beacon dtim-period 1 radio {radio_id}")   # 恢复
            
            # --- short-gi / 11ax-gi: 保护间隔 ---
            log(f"\n>> 4.{radio_id}.7 short-gi / 11ax-gi: 保护间隔")
            suite.run_cmd(f"short-gi enable radio {radio_id} chan-width 20")
            suite.run_cmd(f"short-gi disable radio {radio_id} chan-width 20")
            suite.run_cmd(f"short-gi enable radio {radio_id} chan-width 20")  # 开启
            
            # 11ax-gi (802.11ax 特有)
            for gi in ["0.8", "1.6", "3.2", "auto"]:
                suite.run_cmd(f"11ax-gi {gi} radio {radio_id}")
            suite.run_cmd(f"11ax-gi 0.4 radio {radio_id}", expect_ok=False)  # 非法GI
            suite.run_cmd(f"11ax-gi auto radio {radio_id}")  # 恢复
            
            # --- coverage-area-control: 管理帧功率 ---
            log(f"\n>> 4.{radio_id}.8 coverage-area-control: 管理帧功率")
            for dbm in [0, 10, 20, 32]:
                suite.run_cmd(f"coverage-area-control {dbm} radio {radio_id}")
            suite.run_cmd(f"coverage-area-control 33 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"coverage-area-control 20 radio {radio_id}")
            
            # --- fragment-threshold: 分片阈值 ---
            log(f"\n>> 4.{radio_id}.9 fragment-threshold: 分片阈值")
            for val in [256, 512, 1024, 1500, 2346]:
                suite.run_cmd(f"fragment-threshold {val} radio {radio_id}")
            suite.run_cmd(f"fragment-threshold 255 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"fragment-threshold 2347 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"fragment-threshold 2346 radio {radio_id}")
            
            # --- fragment-burst: 段突发 ---
            suite.run_cmd(f"fragment-burst enable radio {radio_id}")
            suite.run_cmd(f"fragment-burst disable radio {radio_id}")
            suite.run_cmd(f"fragment-burst dynamic radio {radio_id}")
            suite.run_cmd(f"fragment-burst disable radio {radio_id}")
            
            # --- peer-distance: 最远距离 ---
            log(f"\n>> 4.{radio_id}.10 peer-distance: 最远传输距离")
            for val in [1000, 5000, 10000, 25000]:
                suite.run_cmd(f"peer-distance {val} radio {radio_id}")
            suite.run_cmd(f"peer-distance 999 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"peer-distance 25001 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"peer-distance 1000 radio {radio_id}")
            
            self.exit_ap_config()
        
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 5: 协议支持与速率控制
    # =======================================================================
    
    def suite_protocol_rates(self):
        """协议支持开关 / MCS / 速率集."""
        suite = TestSuite("5. Protocol Support & Rate Control")
        
        for radio_id in range(1, NUM_RADIOS + 1):
            radio_type = RADIO_1_TYPE if radio_id == 1 else RADIO_2_TYPE
            band = "2.4G" if radio_type == "802.11b" else "5G"
            
            log(f"\n{'='*50}")
            log(f">> 5.{radio_id} Radio {radio_id} ({band}) 协议/速率")
            log(f"{'='*50}")
            
            self.enter_ap_config()
            
            # --- 协议支持开关 ---
            log(f"\n>> 5.{radio_id}.1 协议支持开关")
            if band == "2.4G":
                # 2.4G 协议
                suite.run_cmd(f"11bsupport enable radio {radio_id}")   # b
                suite.run_cmd(f"11bsupport disable radio {radio_id}")
                suite.run_cmd(f"11gsupport enable radio {radio_id}")   # g
                suite.run_cmd(f"11gsupport disable radio {radio_id}")
                suite.run_cmd(f"11nsupport enable radio {radio_id}")   # n
                suite.run_cmd(f"11nsupport disable radio {radio_id}")
                suite.run_cmd(f"11axsupport enable radio {radio_id}")  # ax (Wi-Fi 6)
                suite.run_cmd(f"11axsupport disable radio {radio_id}")
                # 全开
                suite.run_cmd(f"11bsupport enable radio {radio_id}")
                suite.run_cmd(f"11gsupport enable radio {radio_id}")
                suite.run_cmd(f"11nsupport enable radio {radio_id}")
                suite.run_cmd(f"11axsupport enable radio {radio_id}")
            else:
                # 5G 协议
                suite.run_cmd(f"11asupport enable radio {radio_id}")   # a
                suite.run_cmd(f"11asupport disable radio {radio_id}")
                suite.run_cmd(f"11nsupport enable radio {radio_id}")   # n
                suite.run_cmd(f"11nsupport disable radio {radio_id}")
                suite.run_cmd(f"11acsupport enable radio {radio_id}")  # ac
                suite.run_cmd(f"11acsupport disable radio {radio_id}")
                suite.run_cmd(f"11axsupport enable radio {radio_id}")  # ax
                suite.run_cmd(f"11axsupport disable radio {radio_id}")
                # 全开
                suite.run_cmd(f"11asupport enable radio {radio_id}")
                suite.run_cmd(f"11nsupport enable radio {radio_id}")
                suite.run_cmd(f"11acsupport enable radio {radio_id}")
                suite.run_cmd(f"11axsupport enable radio {radio_id}")
            
            # --- MCS 上限 ---
            log(f"\n>> 5.{radio_id}.2 MCS 上限")
            if band == "2.4G":
                for mcs in [0, 7, 15]:
                    suite.run_cmd(f"802.11n mcs support {mcs} radio {radio_id}")
                suite.run_cmd(f"802.11n mcs support 16 radio {radio_id}", expect_ok=False)
                suite.run_cmd(f"802.11n mcs support 15 radio {radio_id}")
            else:
                suite.run_cmd(f"802.11n mcs support 7 radio {radio_id}")
                suite.run_cmd(f"802.11n mcs support 15 radio {radio_id}")
                suite.run_cmd(f"802.11ac mcs support 9 radio {radio_id}")
                suite.run_cmd(f"802.11ac mcs support 10 radio {radio_id}", expect_ok=False)
                suite.run_cmd(f"802.11ac mcs support 9 radio {radio_id}")
            
            # --- beacon rate: Beacon 发送速率 ---
            log(f"\n>> 5.{radio_id}.3 beacon rate: Beacon 发送速率")
            for rate in [1, 2, 5.5, 6, 11, 12, 24]:
                suite.run_cmd(f"beacon rate {rate} radio {radio_id}")
            suite.run_cmd(f"beacon rate 100 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"beacon rate 6 radio {radio_id}")  # 恢复
            
            # --- rate-set: 速率集 ---
            log(f"\n>> 5.{radio_id}.4 rate-set: 速率集配置")
            if band == "2.4G":
                suite.run_cmd(f"rate-set 11b mandatory 1 2")
                suite.run_cmd(f"rate-set 11b supported 5.5 11")
                suite.run_cmd(f"rate-set 11g mandatory 6 12 24")
                suite.run_cmd(f"rate-set 11g supported 9 18 36 48 54")
            else:
                suite.run_cmd(f"rate-set 11a mandatory 6 12 24")
                suite.run_cmd(f"rate-set 11a supported 9 18 36 48 54")
            
            # --- green-field: PHY 保护模式 (仅 2.4G) ---
            if band == "2.4G":
                log(f"\n>> 5.{radio_id}.5 green-field: PHY 保护")
                suite.run_cmd(f"green-field enable radio {radio_id}")
                suite.run_cmd(f"green-field disable radio {radio_id}")
            
            self.exit_ap_config()
        
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 6: 高级射频特性
    # =======================================================================
    
    def suite_advanced_radio(self):
        """OFDMA / MU-MIMO / mCell / Pre-ax / 供电."""
        suite = TestSuite("6. Advanced Radio Features")
        
        for radio_id in range(1, NUM_RADIOS + 1):
            radio_type = RADIO_1_TYPE if radio_id == 1 else RADIO_2_TYPE
            band = "2.4G" if radio_type == "802.11b" else "5G"
            
            log(f"\n{'='*50}")
            log(f">> 6.{radio_id} Radio {radio_id} ({band}) 高级特性")
            log(f"{'='*50}")
            
            self.enter_ap_config()
            
            # --- OFDMA ---
            log(f"\n>> 6.{radio_id}.1 OFDMA")
            suite.run_cmd(f"ofdma enable radio {radio_id}")
            suite.run_cmd(f"ofdma disable radio {radio_id}")
            suite.run_cmd(f"ofdma enable radio {radio_id}")  # 恢复默认
            
            # --- MU-MIMO ---
            log(f"\n>> 6.{radio_id}.2 MU-MIMO")
            suite.run_cmd(f"mu-mimo enable radio {radio_id}")
            suite.run_cmd(f"mu-mimo disable radio {radio_id}")
            suite.run_cmd(f"mu-mimo enable radio {radio_id}")  # 恢复
            
            # --- mCell ---
            log(f"\n>> 6.{radio_id}.3 mCell (高密优化)")
            suite.run_cmd(f"mcell enable radio {radio_id}")
            suite.run_cmd(f"mcell disable radio {radio_id}")
            
            # --- Pre-ax CCA/TPC ---
            log(f"\n>> 6.{radio_id}.4 Pre-ax DCCA/DTPC")
            suite.run_cmd(f"wopt dcca enable auto radio {radio_id}")
            for level in range(11):  # 0-10
                suite.run_cmd(f"wopt dcca enable {level} radio {radio_id}")
            suite.run_cmd(f"wopt dcca enable auto radio {radio_id}")
            
            suite.run_cmd(f"wopt dtpc enable radio {radio_id}")
            suite.run_cmd(f"wopt dtpc disable radio {radio_id}")
            suite.run_cmd(f"wopt dtpc enable radio {radio_id}")
            
            # --- ldpc / stbc ---
            log(f"\n>> 6.{radio_id}.5 LDPC / STBC")
            suite.run_cmd(f"ldpc radio {radio_id}")
            suite.run_cmd(f"stbc radio {radio_id}")
            
            self.exit_ap_config()
        
        # --- 供电管理 (全局) ---
        log(f"\n>> 6.6 供电管理")
        self.enter_ap_config()
        suite.run_cmd(f"poe-unlimit")  # 全局取消限制
        suite.run_cmd(f"poeout enable")
        suite.run_cmd(f"poeout disable")
        suite.run_cmd(f"poeout default")
        
        # --- AMPDU 参数 ---
        log(f"\n>> 6.7 AMPDU 参数")
        for radio_id in range(1, NUM_RADIOS + 1):
            suite.run_cmd(f"ampdu-retries 10 radio {radio_id}")   # 默认
            suite.run_cmd(f"ampdu-retries 1 radio {radio_id}")    # 最小
            suite.run_cmd(f"ampdu-retries 5 radio {radio_id}")    # 中间
            suite.run_cmd(f"ampdu-retries 0 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"ampdu-retries 11 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"ampdu-retries 10 radio {radio_id}")   # 恢复
            suite.run_cmd(f"ampdu-rts radio {radio_id}")
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 7: RSSI 门限与接入控制
    # =======================================================================
    
    def suite_rssi_access(self):
        """RSSI 门限 / 网络开关 / STA 限制."""
        suite = TestSuite("7. RSSI Thresholds & Access Control")
        
        for radio_id in range(1, NUM_RADIOS + 1):
            radio_type = RADIO_1_TYPE if radio_id == 1 else RADIO_2_TYPE
            band = "2.4G" if radio_type == "802.11b" else "5G"
            
            log(f"\n{'='*50}")
            log(f">> 7.{radio_id} Radio {radio_id} ({band}) RSSI/接入")
            log(f"{'='*50}")
            
            self.enter_ap_config()
            
            # --- 网络开关 ---
            log(f"\n>> 7.{radio_id}.1 网络开关")
            if band == "2.4G":
                suite.run_cmd(f"802.11b network enable radio {radio_id}")
                suite.run_cmd(f"802.11b network disable radio {radio_id}")
                suite.run_cmd(f"802.11b network enable radio {radio_id}")
            else:
                suite.run_cmd(f"802.11a network enable radio {radio_id}")
                suite.run_cmd(f"802.11a network disable radio {radio_id}")
                suite.run_cmd(f"802.11a network enable radio {radio_id}")
            
            # --- response-rssi: Probe Response RSSI 门限 ---
            log(f"\n>> 7.{radio_id}.2 response-rssi: 最小接入 RSSI")
            for rssi in [0, -30, -50, -70, -90, -100]:
                suite.run_cmd(f"response-rssi {rssi} radio {radio_id}")
            suite.run_cmd(f"response-rssi 10 radio {radio_id}", expect_ok=False)  # 正值非法
            suite.run_cmd(f"response-rssi -101 radio {radio_id}", expect_ok=False)  # 超出
            suite.run_cmd(f"response-rssi -70 radio {radio_id}")  # 恢复
            
            # --- assoc-rssi: 保持关联 RSSI 门限 ---
            log(f"\n>> 7.{radio_id}.3 assoc-rssi: 保持关联 RSSI")
            for rssi in [0, -30, -50, -75, -100]:
                suite.run_cmd(f"assoc-rssi {rssi} radio {radio_id}")
            suite.run_cmd(f"assoc-rssi 5 radio {radio_id}", expect_ok=False)
            suite.run_cmd(f"assoc-rssi -75 radio {radio_id}")
            
            # --- sta-limit: STA 数量限制 ---
            log(f"\n>> 7.{radio_id}.4 sta-limit: STA 数量限制")
            for limit in [0, 10, 30, 64, 128, 256]:
                suite.run_cmd(f"sta-limit {limit} radio {radio_id}")
            suite.run_cmd(f"sta-limit 30 radio {radio_id}")
            
            self.exit_ap_config()
        
        # --- 整机 STA 限制 ---
        self.enter_ap_config()
        log(f"\n>> 7.5 整机 STA 限制")
        suite.run_cmd(f"sta-limit 512")
        suite.run_cmd(f"sta-limit 128")
        suite.run_cmd(f"sta-limit 0")  # 不限
        suite.run_cmd(f"sta-limit 64")
        
        # --- 智能隐藏 SSID ---
        log(f"\n>> 7.6 智能隐藏 SSID")
        suite.run_cmd(f"hide-ssid sta-reach-limit")
        suite.run_cmd(f"hide-ssid sta-reach-limit radio 2.4g")
        suite.run_cmd(f"hide-ssid sta-reach-limit radio 5g")
        suite.run_cmd(f"no hide-ssid")
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 8: 节电与链路检测
    # =======================================================================
    
    def suite_power_save(self):
        """U-APSD 节电 / 链路完整性 / 电子书包."""
        suite = TestSuite("8. Power Save & Link Check")
        self.enter_ap_config()
        
        for radio_id in range(1, NUM_RADIOS + 1):
            # --- apsd: U-APSD 节电 ---
            log(f"\n>> 8.{radio_id} apsd: U-APSD 节电 (Radio {radio_id})")
            suite.run_cmd(f"apsd enable radio {radio_id}")
            suite.run_cmd(f"apsd disable radio {radio_id}")
            suite.run_cmd(f"apsd enable radio {radio_id}")  # 恢复默认
        
        # --- link-check: 链路完整性检测 ---
        log(f"\n>> 8.5 link-check: 链路完整性检测")
        suite.run_cmd(f"link-check enable")
        suite.run_cmd(f"no link-check enable")
        
        # --- ebag: 一键电子书包网优 ---
        log(f"\n>> 8.6 ebag: 一键电子书包网优")
        suite.run_cmd(f"ebag")
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 9: 频谱导航 (Band Steering)
    # =======================================================================
    
    def suite_band_steering(self):
        """频谱导航 Band Steering / HE Radio Navigation."""
        suite = TestSuite("9. Band Steering & HE Radio Navigation")
        self.enter_ap_config()
        
        # --- band-select (频谱导航) ---
        log(f"\n>> 9.1 band-select: 频谱导航")
        suite.run_cmd(f"band-select enable radio 1")   # 2.4G 开启频谱导航
        suite.run_cmd(f"band-select disable radio 1")
        suite.run_cmd(f"band-select enable radio 1")
        
        # acceptable-rssi
        for rssi in [-80, -70, -60, -50]:
            suite.run_cmd(f"band-select acceptable-rssi {rssi}")
        suite.run_cmd(f"band-select acceptable-rssi -80")  # 默认
        
        # access-denial (拒绝次数)
        for n in [0, 1, 2, 3, 5, 10]:
            suite.run_cmd(f"band-select access-denial {n}")
        suite.run_cmd(f"band-select access-denial 11", expect_ok=False)
        suite.run_cmd(f"band-select access-denial 2")  # 默认
        
        # age-out (记住时长)
        suite.run_cmd(f"band-select age-out dual-band 60")    # 默认
        suite.run_cmd(f"band-select age-out dual-band 20")
        suite.run_cmd(f"band-select age-out dual-band 120")
        suite.run_cmd(f"band-select age-out suppression 20")  # 默认
        suite.run_cmd(f"band-select age-out suppression 10")
        suite.run_cmd(f"band-select age-out suppression 60")
        
        # probe-count
        for n in [1, 2, 5, 10]:
            suite.run_cmd(f"band-select probe-count {n}")
        suite.run_cmd(f"band-select probe-count 0", expect_ok=False)
        suite.run_cmd(f"band-select probe-count 2")  # 默认
        
        # scan-cycle
        for n in [100, 200, 500, 1000]:
            suite.run_cmd(f"band-select scan-cycle {n}")
        suite.run_cmd(f"band-select scan-cycle 200")  # 默认
        
        suite.run_cmd(f"band-select disable radio 1")  # 关闭
        
        # --- band-optimize he-radio (高效能射频导航) ---
        log(f"\n>> 9.2 band-optimize he-radio: 高效能射频导航")
        suite.run_cmd(f"band-optimize he-radio enable")
        suite.run_cmd(f"band-optimize he-radio enable auto")
        suite.run_cmd(f"band-optimize he-radio enable fixed")
        suite.run_cmd(f"band-optimize he-radio mode 11axonly")
        suite.run_cmd(f"band-optimize he-radio mode 11ac_11ax")
        
        suite.run_cmd(f"band-select he-radio access-denial 2")
        for n in [0, 1, 3, 5, 10]:
            suite.run_cmd(f"band-select he-radio access-denial {n}")
        suite.run_cmd(f"band-select he-radio access-denial 2")  # 默认
        
        suite.run_cmd(f"band-select he-radio probe-count 2")
        for n in [1, 3, 5, 10]:
            suite.run_cmd(f"band-select he-radio probe-count {n}")
        suite.run_cmd(f"band-select he-radio probe-count 2")  # 默认
        
        suite.run_cmd(f"band-optimize he-radio disable")
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 10: WLAN 配置 (可配置数量)
    # =======================================================================
    
    def suite_wlan_config(self):
        """WLAN 创建和部署 (数量由 NUM_WLANS 控制)."""
        suite = TestSuite("10. WLAN Configuration")
        
        # 先进入全局配置模式创建 WLAN 模板
        safe_send("config terminal")
        crt.Sleep(300)
        
        for wlan_idx in range(NUM_WLANS):
            wlan_id = WLAN_START_ID + wlan_idx
            vlan_id = WLAN_VLAN_BASE + wlan_idx
            ssid_name = f"StressTest-WLAN{wlan_id}"
            
            log(f"\n>> 10.{wlan_idx+1} WLAN {wlan_id}: SSID={ssid_name} VLAN={vlan_id}")
            
            # 创建 WLAN
            suite.run_cmd(f"wlan-config {wlan_id} {ssid_name}")
            
            # 进入 WLAN 配置模式
            safe_send(f"wlan-config {wlan_id}")
            crt.Sleep(200)
            
            # SSID 配置
            suite.run_cmd(f"ssid {ssid_name}")
            suite.run_cmd(f"enable-broad-ssid")
            suite.run_cmd(f"nas-id {10000000 + wlan_id}")
            
            # 退出 WLAN 配置，回到全局
            safe_send("exit")
            crt.Sleep(200)
            
            # === 部署 WLAN 到 AP 组 ===
            safe_send(f"ap-group default")
            crt.Sleep(200)
            suite.run_cmd(f"interface-mapping {wlan_id} {vlan_id} radio 802.11b 802.11a")
            
            # STA 限制
            safe_send(f"wlan-config {wlan_id}")
            crt.Sleep(200)
            for limit in [0, 10, 30, 64]:
                suite.run_cmd(f"sta-limit {limit}")
            suite.run_cmd(f"sta-limit 30")
            
            safe_send("exit")
            crt.Sleep(200)
        
        # 回到 ap-config 模式
        self.enter_ap_config()
        
        # --- 默认 SSID (offline-ssid) ---
        log(f"\n>> 10.{NUM_WLANS+1} offline-ssid: 默认 SSID")
        suite.run_cmd(f"offline-ssid Fallback-WiFi")
        suite.run_cmd(f"offline-ssid Fallback-WiFi hide")
        suite.run_cmd(f"no offline-ssid")
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 11: WQOS 带宽控制
    # =======================================================================
    
    def suite_wqos(self):
        """WQOS 流量限速 / 公平调度."""
        suite = TestSuite("11. WQOS Bandwidth Control")
        self.enter_ap_config()
        
        # --- wqos ap-limit: AP 级别限速 ---
        log(f"\n>> 11.1 wqos ap-limit: AP 级别限速")
        suite.run_cmd(f"wqos ap-limit 0")         # 不限
        suite.run_cmd(f"wqos ap-limit 10000")     # 10Mbps
        suite.run_cmd(f"wqos ap-limit 50000")     # 50Mbps
        suite.run_cmd(f"wqos ap-limit 100000")    # 100Mbps
        suite.run_cmd(f"wqos ap-limit 1000000")   # 1Gbps
        suite.run_cmd(f"wqos ap-limit 100000")    # 恢复
        
        # --- wqos sta-limit: STA 级别限速 ---
        log(f"\n>> 11.2 wqos sta-limit: STA 级别限速")
        suite.run_cmd(f"wqos sta-limit 0")
        suite.run_cmd(f"wqos sta-limit 1000")     # 1Mbps
        suite.run_cmd(f"wqos sta-limit 5000")     # 5Mbps
        suite.run_cmd(f"wqos sta-limit 20000")    # 20Mbps
        suite.run_cmd(f"wqos sta-limit 10000")    # 恢复
        
        # --- fair-schedule: 公平调度 ---
        log(f"\n>> 11.3 fair-schedule: 公平调度")
        suite.run_cmd(f"wqos fair-schedule enable")
        suite.run_cmd(f"wqos fair-schedule disable")
        suite.run_cmd(f"wqos fair-schedule enable")  # 恢复
        
        # --- sta-fair: STA 优先级 ---
        log(f"\n>> 11.4 sta-fair: STA 优先级")
        suite.run_cmd(f"sta-fair 00:11:22:33:44:55 priority 1")
        suite.run_cmd(f"sta-fair 00:11:22:33:44:55 priority 6")  # 最高
        suite.run_cmd(f"sta-fair 00:11:22:33:44:55 priority 0", expect_ok=False)
        suite.run_cmd(f"sta-fair aa:bb:cc:dd:ee:ff priority 3")
        suite.run_cmd(f"no sta-fair 00:11:22:33:44:55")
        suite.run_cmd(f"no sta-fair aa:bb:cc:dd:ee:ff")
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 12: CAPWAP 参数
    # =======================================================================
    
    def suite_capwap(self):
        """CAPWAP 隧道 / DTLS / 心跳 / 分片."""
        suite = TestSuite("12. CAPWAP Tunnel Parameters")
        self.enter_ap_config()
        
        # --- 静态 AC 地址 ---
        log(f"\n>> 12.1 acip: 静态 AC 地址")
        suite.run_cmd(f"acip ipv4 {AC_PRIMARY_IP}")
        if AC_SECONDARY_IP:
            suite.run_cmd(f"acip ipv4 {AC_PRIMARY_IP} {AC_SECONDARY_IP}")
        
        # --- CAPWAP 心跳 ---
        log(f"\n>> 12.2 echo-interval: CAPWAP 心跳间隔")
        for interval in [5, 10, 30, 60, 120]:
            suite.run_cmd(f"echo-interval {interval}")
        suite.run_cmd(f"echo-interval 0", expect_ok=False)
        suite.run_cmd(f"echo-interval 30")  # 默认
        
        # --- CAPWAP 重传 ---
        log(f"\n>> 12.3 capwap max-retransmit: CAPWAP 重传")
        for n in [1, 2, 3, 5, 10]:
            suite.run_cmd(f"capwap max-retransmit {n}")
        suite.run_cmd(f"capwap max-retransmit 3")  # 默认
        
        # --- CAPWAP DTLS 加密 ---
        log(f"\n>> 12.4 capwap dtls: DTLS 加密")
        suite.run_cmd(f"capwap dtls enable")
        suite.run_cmd(f"capwap dtls disable")
        suite.run_cmd(f"capwap dtls enable")
        
        # --- CAPWAP 分片 ---
        log(f"\n>> 12.5 capwap fragment: CAPWAP 分片")
        suite.run_cmd(f"capwap fragment enable")
        suite.run_cmd(f"capwap fragment disable")
        
        # --- CAPWAP MTU ---
        log(f"\n>> 12.6 capwap mtu: CAPWAP MTU")
        for mtu in [576, 1000, 1400, 1500, 9000]:
            suite.run_cmd(f"capwap mtu {mtu}")
        suite.run_cmd(f"capwap mtu 1500")  # 恢复
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 13: 安全配置 (RSNA)
    # =======================================================================
    
    def suite_security(self):
        """WLAN 安全: PSK/802.1X/WEP/MAB."""
        suite = TestSuite("13. Security (RSNA/WPA/WEP)")
        
        # 安全配置在 WLAN 模式下，需要先创建 WLAN
        safe_send("config terminal")
        crt.Sleep(300)
        
        # 使用 WLAN 1 做安全测试
        test_wlan = WLAN_START_ID
        safe_send(f"wlan-config {test_wlan}")
        crt.Sleep(200)
        
        # --- WPA (TKIP/AES) ---
        log(f"\n>> 13.1 WPA 认证")
        suite.run_cmd(f"security wpa enable")
        suite.run_cmd(f"security wpa ciphers aes enable")
        suite.run_cmd(f"security wpa ciphers tkip enable")
        suite.run_cmd(f"security wpa ciphers tkip disable")
        suite.run_cmd(f"security wpa akm psk enable")
        suite.run_cmd(f"security wpa akm 802.1x enable")
        suite.run_cmd(f"security wpa akm 802.1x disable")
        suite.run_cmd(f"security wpa akm psk set-key ascii StressTest123")
        suite.run_cmd(f"security wpa akm psk set-key ascii ShortPW")  # 最短8字符
        suite.run_cmd(f"security wpa akm psk set-key ascii MaxLength-63-Characters-01234567890123456789012345678901234")  # 最长
        suite.run_cmd(f"security wpa akm psk set-key hex 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        suite.run_cmd(f"security wpa disable")
        
        # --- RSN (WPA2) ---
        log(f"\n>> 13.2 RSN (WPA2) 认证")
        suite.run_cmd(f"security rsn enable")
        suite.run_cmd(f"security rsn ciphers aes enable")
        suite.run_cmd(f"security rsn ciphers tkip enable")
        suite.run_cmd(f"security rsn ciphers tkip disable")
        suite.run_cmd(f"security rsn akm psk enable")
        suite.run_cmd(f"security rsn akm 802.1x enable")
        suite.run_cmd(f"security rsn akm 802.1x disable")
        suite.run_cmd(f"security rsn akm psk set-key ascii RSN-StressTest123")
        suite.run_cmd(f"security rsn disable")
        
        # --- WEP ---
        log(f"\n>> 13.3 WEP 加密")
        suite.run_cmd(f"security static-wep-key encryption 40 hex 1 aabbccddee")
        suite.run_cmd(f"security static-wep-key encryption 104 hex 1 aabbccddeeff0011223344556677")
        suite.run_cmd(f"security static-wep-key authentication open")
        suite.run_cmd(f"security static-wep-key authentication share-key")
        
        # --- MAB ---
        log(f"\n>> 13.4 MAB (MAC旁路认证)")
        suite.run_cmd(f"dot1x-mab")
        suite.run_cmd(f"no dot1x-mab")
        
        # --- 认证超时参数 ---
        log(f"\n>> 13.5 认证超时参数")
        suite.run_cmd(f"authtimeout paircount 4")
        suite.run_cmd(f"authtimeout paircount 1")
        suite.run_cmd(f"authtimeout paircount 10")
        suite.run_cmd(f"authtimeout paircount 4")
        
        suite.run_cmd(f"authtimeout pairtime 1200")  # 默认
        suite.run_cmd(f"authtimeout pairtime 500")
        suite.run_cmd(f"authtimeout pairtime 3000")
        suite.run_cmd(f"authtimeout pairtime 1200")
        
        suite.run_cmd(f"authtimeout groupcount 4")
        suite.run_cmd(f"authtimeout groupcount 1")
        suite.run_cmd(f"authtimeout groupcount 10")
        suite.run_cmd(f"authtimeout groupcount 4")
        
        suite.run_cmd(f"authtimeout grouptime 1200")
        suite.run_cmd(f"authtimeout grouptime 500")
        suite.run_cmd(f"authtimeout grouptime 3000")
        suite.run_cmd(f"authtimeout grouptime 1200")
        
        suite.run_cmd(f"authtimeout forbidcount 5")
        suite.run_cmd(f"authtimeout forbidcount 1")
        suite.run_cmd(f"authtimeout forbidcount 20")
        suite.run_cmd(f"authtimeout forbidcount 5")
        
        suite.run_cmd(f"authtimeout forbidtime 60")
        suite.run_cmd(f"authtimeout forbidtime 10")
        suite.run_cmd(f"authtimeout forbidtime 3600")
        suite.run_cmd(f"authtimeout forbidtime 60")
        
        # --- WEB 防抖 ---
        suite.run_cmd(f"webauth prevent-jitter 300")
        suite.run_cmd(f"webauth prevent-jitter 0")
        suite.run_cmd(f"webauth prevent-jitter 86400")
        suite.run_cmd(f"webauth prevent-jitter 300")
        
        safe_send("exit")
        crt.Sleep(200)
        
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 14: NFPP 抗攻击 (全局级)
    # =======================================================================
    
    def suite_nfpp(self):
        """NFPP ARP/IP/ICMP/DHCP 抗攻击."""
        suite = TestSuite("14. NFPP Network Protection")
        
        safe_send("config terminal")
        crt.Sleep(300)
        safe_send("nfpp")
        crt.Sleep(200)
        
        # --- ARP 抗攻击 ---
        log(f"\n>> 14.1 ARP 抗攻击")
        suite.run_cmd(f"arp-guard enable")
        suite.run_cmd(f"arp-guard rate-limit per-src-ip 100")
        suite.run_cmd(f"arp-guard rate-limit per-src-ip 50")
        suite.run_cmd(f"arp-guard rate-limit per-src-ip 500")
        suite.run_cmd(f"arp-guard rate-limit per-src-ip 9999")
        suite.run_cmd(f"arp-guard rate-limit per-src-ip 100")
        
        suite.run_cmd(f"arp-guard attack-threshold per-src-ip 150")
        suite.run_cmd(f"arp-guard attack-threshold per-src-ip 150")
        suite.run_cmd(f"arp-guard attack-threshold per-src-ip 9999")
        suite.run_cmd(f"arp-guard attack-threshold per-src-ip 150")
        
        suite.run_cmd(f"arp-guard isolate-period 300")
        suite.run_cmd(f"arp-guard isolate-period 0")    # 不隔离
        suite.run_cmd(f"arp-guard isolate-period 86400") # 最大
        suite.run_cmd(f"arp-guard isolate-period permanent")
        suite.run_cmd(f"arp-guard isolate-period 300")  # 恢复
        
        suite.run_cmd(f"arp-guard scan-threshold 100")
        suite.run_cmd(f"arp-guard scan-threshold 10")
        suite.run_cmd(f"arp-guard scan-threshold 1000")
        suite.run_cmd(f"arp-guard scan-threshold 100")
        
        suite.run_cmd(f"arp-guard monitor-period 600")
        suite.run_cmd(f"arp-guard monitor-period 180")
        suite.run_cmd(f"arp-guard monitor-period 86400")
        suite.run_cmd(f"arp-guard monitor-period 600")
        
        suite.run_cmd(f"arp-guard disable")
        
        # --- IP 防扫描 ---
        log(f"\n>> 14.2 IP 防扫描")
        suite.run_cmd(f"ip-guard enable")
        suite.run_cmd(f"ip-guard rate-limit per-src-ip 50")
        suite.run_cmd(f"ip-guard rate-limit per-src-ip 10")
        suite.run_cmd(f"ip-guard rate-limit per-src-ip 9999")
        suite.run_cmd(f"ip-guard rate-limit per-src-ip 50")
        suite.run_cmd(f"ip-guard disable")
        
        # --- ICMP 抗攻击 ---
        log(f"\n>> 14.3 ICMP 抗攻击")
        suite.run_cmd(f"icmp-guard enable")
        suite.run_cmd(f"icmp-guard rate-limit 100")
        suite.run_cmd(f"icmp-guard rate-limit 10")
        suite.run_cmd(f"icmp-guard rate-limit 9999")
        suite.run_cmd(f"icmp-guard rate-limit 100")
        suite.run_cmd(f"icmp-guard disable")
        
        # --- DHCP 抗攻击 ---
        log(f"\n>> 14.4 DHCP 抗攻击")
        suite.run_cmd(f"dhcp-guard enable")
        suite.run_cmd(f"dhcp-guard rate-limit 60")
        suite.run_cmd(f"dhcp-guard rate-limit 10")
        suite.run_cmd(f"dhcp-guard rate-limit 9999")
        suite.run_cmd(f"dhcp-guard rate-limit 60")
        suite.run_cmd(f"dhcp-guard disable")
        
        safe_send("exit")
        crt.Sleep(200)
        
        self.suites.append(suite)
        log(suite.summary())
        return suite
    
    # =======================================================================
    # Suite 15: show 命令验证 (不修改配置)
    # =======================================================================
    
    def suite_show_commands(self):
        """执行 show 命令验证配置状态."""
        suite = TestSuite("15. Show Commands Verification")
        self.enter_ap_config()
        
        log(f"\n>> 15.1 show 命令验证")
        show_cmds = [
            "show ap-config summary",
            f"show ap-config ap-name {TARGET_AP_NAME}",
            "show ap-status",
            "show wlan-config summary",
            "show sta-list",
            "show capwap state",
            "show ac-controller",
        ]
        
        for cmd in show_cmds:
            # show 命令不期望失败
            result = execute_cmd(cmd, expect_ok=True)
            suite.results.append(result)
            if result.success:
                suite.pass_count += 1
            else:
                suite.fail_count += 1
            crt.Sleep(500)
        
        self.exit_ap_config()
        self.suites.append(suite)
        log(suite.summary())
        return suite
    

# ===========================================================================
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                    主流程 (MAIN)                                         ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# ===========================================================================

def setup_log_file():
    """设置日志文件路径."""
    global LOG_FILE
    if not LOG_FILE:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        LOG_FILE = os.path.join(script_dir, f"ap_stress_test_{TARGET_AP_NAME}_{timestamp}.log")

def print_banner():
    """打印脚本启动横幅."""
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║           RG-AC AP 配置拷机脚本 (AP Configuration Stress Test)           ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Target AP:    {TARGET_AP_NAME:<55s}║
║  Radios:       {NUM_RADIOS:<55d}║
║  WLANs:        {NUM_WLANS:<55d}║
║  Test Mode:    {TEST_MODE:<55s}║
║  Log File:     {LOG_FILE:<55s}║
╚══════════════════════════════════════════════════════════════════════════╝
"""
    log(banner.strip())
    crt.Screen.Send(f"\r\n{banner}\r\n")

def main():
    """主函数."""
    global crt
    crt = get_crt()
    
    # 设置日志
    setup_log_file()
    
    # 确保日志目录存在
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # 初始化日志文件
    with open(LOG_FILE, "w", encoding="utf-8") as f:
        f.write(f"# AP Configuration Stress Test Log\n")
        f.write(f"# Target: {TARGET_AP_NAME} | Radios: {NUM_RADIOS} | WLANs: {NUM_WLANS}\n")
        f.write(f"# Started: {datetime.now().isoformat()}\n")
        f.write(f"# Mode: {TEST_MODE}\n")
        f.write(f"{'='*70}\n\n")
    
    print_banner()
    
    # 创建测试实例
    test = APConfigStressTest()
    test.start_time = datetime.now()
    
    # === 执行测试套件 ===
    
    log("\n" + "="*70)
    log("PHASE 1: AP 基础配置 (身份/管理/AC冗余)")
    log("="*70)
    test.suite_ap_identity()
    test.suite_ap_admin()
    test.suite_ap_priority_backup()
    
    log("\n" + "="*70)
    log("PHASE 2: 射频参数穷举 (信道/功率/带宽/天线/GI/MCS)")
    log("="*70)
    test.suite_radio_params()
    test.suite_protocol_rates()
    test.suite_advanced_radio()
    
    log("\n" + "="*70)
    log("PHASE 3: 接入控制与优化 (RSSI/STA限制/节电/频谱导航)")
    log("="*70)
    test.suite_rssi_access()
    test.suite_power_save()
    test.suite_band_steering()
    
    log("\n" + "="*70)
    log("PHASE 4: WLAN 配置 (WLAN部署/WQOS)")
    log("="*70)
    test.suite_wlan_config()
    test.suite_wqos()
    
    log("\n" + "="*70)
    log("PHASE 5: CAPWAP 隧道与安全")
    log("="*70)
    test.suite_capwap()
    test.suite_security()
    test.suite_nfpp()
    
    log("\n" + "="*70)
    log("PHASE 6: 配置验证 (show命令)")
    log("="*70)
    test.suite_show_commands()
    
    # === 汇总报告 ===
    test.end_time = datetime.now()
    duration = test.end_time - test.start_time
    
    total_pass = sum(s.pass_count for s in test.suites)
    total_fail = sum(s.fail_count for s in test.suites)
    total_skip = sum(s.skip_count for s in test.suites)
    total_all = total_pass + total_fail + total_skip
    
    report = f"""
╔══════════════════════════════════════════════════════════════════════════╗
║                         拷 机 完 成 报 告                                 ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Duration:     {str(duration):<55s}║
║  Total PASS:   {total_pass:<55d}║
║  Total FAIL:   {total_fail:<55d}║
║  Total SKIP:   {total_skip:<55d}║
║  Total CMDs:   {total_all:<55d}║
║  Success Rate: {total_pass/total_all*100 if total_all > 0 else 0:.1f}%{'':<43s}║
╠══════════════════════════════════════════════════════════════════════════╣
║  Suite Breakdown:                                                       ║
"""
    
    for s in test.suites:
        s_total = s.pass_count + s.fail_count + s.skip_count
        s_rate = s.pass_count / s_total * 100 if s_total > 0 else 0
        report += f"║  {s.name:<30s} | P:{s.pass_count:4d} F:{s.fail_count:4d} S:{s.skip_count:4d} ({s_rate:5.1f}%){'':>8s}║\n"
    
    report += f"""╚══════════════════════════════════════════════════════════════════════════╝
"""
    
    log(report)
    crt.Screen.Send(f"\r\n{report}\r\n")
    
    # 写入日志文件
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(report)
        f.write(f"\n# Finished: {datetime.now().isoformat()}\n")
    
    # 弹窗提示
    crt.Dialog.MessageBox(
        f"AP Configuration Stress Test Complete\n\n"
        f"PASS: {total_pass}  FAIL: {total_fail}  SKIP: {total_skip}\n"
        f"Success Rate: {total_pass/total_all*100:.1f}%\n\n"
        f"Log: {LOG_FILE}",
        "拷机完成"
    )
    
    return total_fail == 0, test

# ===========================================================================
# 脚本入口
# ===========================================================================

if __name__ == "__main__":
    success, test_instance = main()
    
    if not success:
        fail_count = sum(s.fail_count for s in test_instance.suites)
        crt.Dialog.MessageBox(
            f"WARNING: {fail_count} tests FAILED.\n"
            f"Please check the log file for details.\n\n"
            f"Log: {LOG_FILE}",
            "拷机失败"
        )
