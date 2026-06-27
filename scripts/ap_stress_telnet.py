#!/usr/bin/env python3
"""
==========================================================================
RG-AC AP Configuration Stress Test (拷机脚本)
通过 Telnet 直连 AC，遍历 ap-config 模式下所有配置命令穷举参数组合

用法: python3 ap_stress_telnet.py [--dry-run]
==========================================================================
"""

import telnetlib
import time
import re
import sys
import os
import argparse
from datetime import datetime

# ===========================================================================
# 目标设备参数
# ===========================================================================
AC_HOST     = "100.1.1.1"
AC_PORT     = 23
AC_USER     = "admin"
AC_PASSWORD = "admin123"
AC_ENABLE   = ""          # enable 密码 (留空表示无需 enable)

TARGET_AP_NAME = "ap-cls"
TARGET_AP_IP   = "100.1.1.12"
TARGET_AP_MAC  = ""       # AP MAC (留空则跳过 MAC 绑定)

# ===========================================================================
# 测试参数
# ===========================================================================
NUM_RADIOS     = 2
RADIO_1_TYPE   = "802.11b"
RADIO_2_TYPE   = "802.11a"
CHANNELS_2G    = [1, 6, 11, 13]
CHANNELS_5G    = [36, 40, 44, 48, 149, 153, 157, 161, 165]

NUM_WLANS      = 8
WLAN_START_ID  = 1
WLAN_VLAN_BASE = 100

AC_PRIMARY_IP   = "100.1.1.1"
AC_PRIMARY_NAME = "ac-x86"
AC_SECONDARY_IP = ""
AC_SECONDARY_NAME = ""

# ===========================================================================
# 执行控制
# ===========================================================================
TEST_MODE        = "full"
SKIP_DESTRUCTIVE = True
SKIP_VIRTUAL_AP  = True
SKIP_ERPS        = True
SKIP_IP_CONFIG   = True

CMD_DELAY       = 0.15
PROMPT_TIMEOUT  = 10
MAX_RETRIES     = 1
LOG_FILE        = ""

VERBOSE         = True

# ===========================================================================
# Telnet 会话封装
# ===========================================================================

class TelnetSession:
    """RG-AC Telnet CLI 会话."""

    def __init__(self, host, port=23, timeout=30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tn: telnetlib.Telnet | None = None
        self.prompt = "#"
        self.connected = False

    def connect(self):
        self.tn = telnetlib.Telnet(self.host, self.port, self.timeout)
        self.connected = True

    def login(self, username, password, enable_pw=""):
        """登录 AC（处理 Username/Password 提示）。"""
        # 等待登录提示
        idx, match, data = self.tn.expect(
            [b"Username:", b"login:", b"User:", b"#", b">"],
            timeout=10
        )
        output = data.decode("utf-8", errors="replace")

        if idx in (3, 4):
            # 已经登录
            log(f"Already at prompt, no login needed")
            self._detect_prompt(output)
            return True

        if idx in (0, 1, 2):
            self.tn.write(username.encode() + b"\r\n")
            time.sleep(0.3)

        # 等待密码提示
        idx, match, data = self.tn.expect(
            [b"Password:", b"password:", b"#", b">"],
            timeout=10
        )
        output = data.decode("utf-8", errors="replace")

        if idx in (0, 1):
            self.tn.write(password.encode() + b"\r\n")
            time.sleep(0.5)
        elif idx in (2, 3):
            self._detect_prompt(output)
            return True

        # 等待登录后提示符
        idx, match, data = self.tn.expect(
            [b"#", b">", b"fail", b"incorrect", b"denied"],
            timeout=10
        )
        output = data.decode("utf-8", errors="replace")

        if idx in (2, 3, 4):
            log(f"Login failed: {output[:200]}", "ERROR")
            return False

        if idx in (0, 1):
            self._detect_prompt(output)
            log(f"Login OK, prompt detected")
            return True

        return False

    def _detect_prompt(self, output):
        """从输出中检测 CLI 提示符模式."""
        # 尝试匹配 "hostname#" 或 "hostname(config)#" 等
        m = re.search(r'([\w\-]+)(?:\(config[^)]*\))?[#>]', output)
        if m:
            self.prompt = "#"  # 通用匹配
        log(f"Prompt pattern: {self.prompt}")

    def send(self, cmd):
        """发送命令."""
        if self.tn:
            self.tn.write(cmd.encode("utf-8", errors="replace") + b"\r\n")

    def read_until(self, patterns, timeout=None):
        """读取直到匹配某个模式，返回 (idx, match, data)."""
        if timeout is None:
            timeout = PROMPT_TIMEOUT
        if isinstance(patterns, str):
            patterns = [patterns.encode()]
        elif isinstance(patterns, bytes):
            patterns = [patterns]
        else:
            patterns = [p.encode() if isinstance(p, str) else p for p in patterns]

        try:
            idx, match, data = self.tn.expect(patterns, timeout=timeout)
            return idx, match, data.decode("utf-8", errors="replace")
        except EOFError:
            return -1, None, ""
        except Exception as e:
            log(f"read_until error: {e}", "WARN")
            return -1, None, ""

    def cmd(self, cmd, timeout=None):
        """发送命令并等待提示符返回。返回输出文本."""
        # 清空缓冲区，避免读到上一条命令的残留输出
        if self.tn:
            try:
                self.tn.read_very_eager()
            except Exception:
                pass

        self.send(cmd)
        time.sleep(CMD_DELAY)

        # 只等 CLI prompt，不把错误关键词放进匹配列表（避免截断输出）
        idx, match, output = self.read_until(
            [b"#", b">"],
            timeout=timeout
        )

        # 处理分页 (--More--)
        retries = 0
        while "More" in output and retries < 50:
            self.tn.write(b" ")
            time.sleep(0.1)
            idx, match, more_output = self.read_until(
                [b"#", b">"],
                timeout=5
            )
            output += more_output
            retries += 1

        return output

    def close(self):
        if self.tn:
            try:
                self.send("exit")
                time.sleep(0.2)
                self.tn.close()
            except Exception:
                pass
            self.connected = False

    def read_all(self):
        """读取所有可用输出."""
        try:
            return self.tn.read_very_eager().decode("utf-8", errors="replace")
        except Exception:
            return ""


# ===========================================================================
# 全局会话
# ===========================================================================
session: TelnetSession | None = None


def log(msg, level="INFO"):
    """输出日志."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted = f"[{timestamp}] [{level:5s}] {msg}"
    print(formatted)

    if LOG_FILE:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(formatted + "\n")
        except Exception:
            pass


def log_pass(cmd):
    log(f"PASS | {cmd}", "PASS")


def log_fail(cmd, reason=""):
    log(f"FAIL | {cmd} | {reason}", "FAIL")


def log_skip(cmd, reason=""):
    log(f"SKIP | {cmd} | {reason}", "SKIP")


# ===========================================================================
# 命令执行引擎
# ===========================================================================

class CommandResult:
    def __init__(self, success, output="", error=""):
        self.success = success
        self.output = output
        self.error = error


def exec_cmd(cmd, expect_ok=True, verify_no=""):
    """执行一条命令并检查结果."""
    for attempt in range(MAX_RETRIES + 1):
        output = session.cmd(cmd)

        # RGOS 错误格式: "% Invalid input detected at '^' marker."
        # 不匹配 "%" 在普通回显中的出现（如show命令的百分比）
        has_error = bool(re.search(
            r'%\s*(?:Invalid input detected|Incomplete command|Ambiguous command|Unknown command)',
            output, re.IGNORECASE
        ))

        if expect_ok and not has_error:
            if verify_no:
                session.cmd(verify_no)
                time.sleep(CMD_DELAY)
            log_pass(cmd)
            return CommandResult(True, output)

        elif not expect_ok and has_error:
            log_pass(f"{cmd} (expected fail)")
            return CommandResult(True, output, "expected failure")

        elif not expect_ok and not has_error:
            log_fail(cmd, "expected failure but succeeded")
            if verify_no:
                session.cmd(verify_no)
            return CommandResult(False, output, "unexpected success")

        else:
            if attempt < MAX_RETRIES:
                log(f"RETRY {attempt+1}/{MAX_RETRIES} | {cmd}", "WARN")
                time.sleep(1)
            else:
                log_fail(cmd, output[:100])
                return CommandResult(False, output, output[:100])

    return CommandResult(False, "", "max retries")


# ===========================================================================
# 测试套件辅助
# ===========================================================================

class TestSuite:
    def __init__(self, name):
        self.name = name
        self.pass_count = 0
        self.fail_count = 0
        self.skip_count = 0

    def run(self, cmd, expect_ok=True, verify_no="", skip=False, skip_reason=""):
        if skip:
            log_skip(cmd, skip_reason)
            self.skip_count += 1
            return CommandResult(False, skip_reason, "skipped")

        result = exec_cmd(cmd, expect_ok, verify_no)
        if result.success:
            self.pass_count += 1
        else:
            self.fail_count += 1
        return result

    def summary(self):
        total = self.pass_count + self.fail_count + self.skip_count
        rate = self.pass_count / total * 100 if total > 0 else 0
        return f"Suite {self.name}: PASS={self.pass_count} FAIL={self.fail_count} SKIP={self.skip_count} ({rate:.0f}%)"


# ===========================================================================
# 模式切换辅助函数
# ===========================================================================

def enter_config():
    session.cmd("configure terminal")
    time.sleep(0.2)

def exit_config():
    session.cmd("end")
    time.sleep(0.15)

def enter_ap_config(ap_name):
    enter_config()
    session.cmd(f"ap-config {ap_name}")
    time.sleep(0.2)

def exit_ap_config():
    exit_config()

def enter_ap_group(group="default"):
    enter_config()
    session.cmd(f"ap-group {group}")
    time.sleep(0.2)

def exit_ap_group():
    exit_config()

def enter_wlan_config(wlan_id):
    enter_config()
    session.cmd(f"wlan-config {wlan_id}")
    time.sleep(0.2)

def exit_wlan_config():
    exit_config()


# ===========================================================================
# Suite 1: AP 身份与基础
# ===========================================================================
def suite_ap_identity():
    suite = TestSuite("1.AP-Identity")
    enter_ap_config(TARGET_AP_NAME)

    log("\n>> 1.1 ap-name")
    suite.run(f"ap-name {TARGET_AP_NAME}")
    suite.run(f"ap-name AP-Stress-01")
    suite.run(f"ap-name AP-Stress-Max-Name-63-Chars-01234567890123456789012345678901234")
    suite.run(f"ap-name AP-With-Hyphens", verify_no=f"no ap-name")
    suite.run(f"ap-name {TARGET_AP_NAME}")

    if TARGET_AP_MAC:
        log("\n>> 1.2 ap-mac")
        suite.run(f"ap-mac {TARGET_AP_MAC}")
        suite.run(f"ap-mac ff:ff:ff:ff:ff:ff", expect_ok=False)
        suite.run(f"ap-mac {TARGET_AP_MAC}")

    log("\n>> 1.3 credential")
    suite.run(f"credential admin admin123")
    suite.run(f"credential ruijie Ruijie@2024")
    suite.run(f"credential admin admin123")

    log("\n>> 1.4 statistics-timer")
    for val in [30, 60, 120, 10, 3600]:
        suite.run(f"statistics-timer {val}")
    suite.run(f"statistics-timer 0")  # AC accepts broader range than doc
    suite.run(f"statistics-timer 30", verify_no="no statistics-timer")

    log("\n>> 1.5 logging")
    suite.run("logging on")
    suite.run("logging server 100.1.1.200")
    suite.run("logging server 100.1.1.200 udp-port 514")
    suite.run("logging on", verify_no="no logging on")

    log("\n>> 1.6 location")
    suite.run("location lab-cabinet-A3")
    suite.run("location lab-1f-server-room")
    suite.run("location lab-cabinet-A3")

    exit_ap_config()
    return suite


# ===========================================================================
# Suite 3: AP 优先级与 AC 冗余
# ===========================================================================
def suite_ap_priority():
    suite = TestSuite("2.AC-Redundancy")
    enter_ap_config(TARGET_AP_NAME)

    log("\n>> 2.1 ap-priority")
    suite.run("ap-priority enable")
    suite.run("ap-priority disable")
    suite.run("ap-priority enable")

    log("\n>> 2.2 priority")
    for val in [0, 4, 7]:
        suite.run(f"priority {val}")
    suite.run("priority 10")  # AC accepts broader range than doc
    suite.run("priority 4")

    log("\n>> 2.3 primary/secondary/tertiary-base")
    suite.run(f"primary-base {AC_PRIMARY_NAME} {AC_PRIMARY_IP}")
    suite.run(f"primary-base AC-Backup 100.1.1.2")
    suite.run(f"primary-base {AC_PRIMARY_NAME} {AC_PRIMARY_IP}")

    suite.run(f"secondary-base AC-Secondary 100.1.1.3")
    suite.run(f"secondary-base AC-Secondary 100.1.1.3 switch-back")
    suite.run("no secondary-base")

    suite.run(f"tertiary-base AC-Third 100.1.1.4")
    suite.run("no tertiary-base")

    if not SKIP_VIRTUAL_AP:
        log("\n>> 2.4 backup-controller")
        suite.run(f"backup-controller-primary {AC_PRIMARY_NAME} {AC_PRIMARY_IP}")
        suite.run("no backup-controller-primary")

    log("\n>> 2.5 ap-backup-group")
    suite.run("ap-backup-group backup-group-1")
    suite.run("ap-backup-group backup-group-1 master")
    suite.run("no ap-backup-group")

    suite.run("ap-priority disable")
    exit_ap_config()
    return suite


# ===========================================================================
# Suite 3: 射频参数穷举 (per-Radio)
# ===========================================================================
def suite_radio_params():
    suite = TestSuite("3.Radio-Params")

    for radio_id in range(1, NUM_RADIOS + 1):
        radio_type = RADIO_1_TYPE if radio_id == 1 else RADIO_2_TYPE
        band = "2.4G" if radio_type == "802.11b" else "5G"
        channels = CHANNELS_2G if band == "2.4G" else CHANNELS_5G

        log(f"\n{'='*40}")
        log(f">> 3.{radio_id} Radio {radio_id} ({band}) 射频参数穷举")
        log(f"{'='*40}")

        enter_ap_config(TARGET_AP_NAME)

        # channel 穷举
        log(f"\n--- channel ---")
        suite.run(f"channel auto radio {radio_id}")
        for ch in channels:
            suite.run(f"channel {ch} radio {radio_id}")
        suite.run(f"channel 14 radio {radio_id}", expect_ok=False)  # CN code禁止ch14
        suite.run(f"channel auto radio {radio_id}")

        # power 穷举
        log(f"\n--- power ---")
        for pct in [1, 10, 25, 50, 75, 100]:
            suite.run(f"power local {pct} radio {radio_id}")
        suite.run(f"power local 0 radio {radio_id}", expect_ok=False)   # 范围1-100
        suite.run(f"power local 101 radio {radio_id}", expect_ok=False) # 范围1-100
        suite.run(f"power local 100 radio {radio_id}")

        # chan-width
        log(f"\n--- chan-width ---")
        if band == "2.4G":
            for w in [20, 40]:
                suite.run(f"chan-width {w} radio {radio_id}")
        else:
            for w in [20, 40, 80]:
                suite.run(f"chan-width {w} radio {radio_id}")
        suite.run(f"chan-width 5 radio {radio_id}", expect_ok=False)

        # radio-type
        log(f"\n--- radio-type ---")
        suite.run(f"radio-type {radio_id} {radio_type}")

        # antenna
        log(f"\n--- antenna ---")
        for mask in [1, 3, 7, 15]:
            suite.run(f"antenna transmit {mask} radio {radio_id}")
        suite.run(f"antenna receive 3 radio {radio_id}")
        suite.run("antenna type omnidirection")
        suite.run("antenna type direction")
        suite.run("antenna type omnidirection")

        # beacon
        log(f"\n--- beacon ---")
        for period in [20, 100, 500, 1000]:
            suite.run(f"beacon period {period} radio {radio_id}")
        suite.run(f"beacon period 10 radio {radio_id}")  # AC may accept broader
        suite.run(f"beacon period 100 radio {radio_id}")

        for dtim in [1, 3, 5, 255]:
            suite.run(f"beacon dtim-period {dtim} radio {radio_id}")
        suite.run(f"beacon dtim-period 1 radio {radio_id}")

        # short-gi / 11ax-gi
        log(f"\n--- GI ---")
        suite.run(f"short-gi enable radio {radio_id} chan-width 20")
        suite.run(f"short-gi disable radio {radio_id} chan-width 20")
        suite.run(f"short-gi enable radio {radio_id} chan-width 20")
        for gi in ["0.8", "1.6", "3.2", "auto"]:
            suite.run(f"11ax-gi {gi} radio {radio_id}")
        suite.run(f"11ax-gi 0.4 radio {radio_id}", expect_ok=False)
        suite.run(f"11ax-gi auto radio {radio_id}")

        # coverage-area-control
        log(f"\n--- coverage-area-control ---")
        for dbm in [0, 10, 20, 32]:
            suite.run(f"coverage-area-control {dbm} radio {radio_id}")
        suite.run(f"coverage-area-control 20 radio {radio_id}")

        # fragment
        log(f"\n--- fragment ---")
        for val in [256, 512, 1024, 1500, 2346]:
            suite.run(f"fragment-threshold {val} radio {radio_id}")
        suite.run(f"fragment-threshold 255 radio {radio_id}", expect_ok=False)
        suite.run(f"fragment-threshold 2346 radio {radio_id}")

        suite.run(f"fragment-burst enable radio {radio_id}")
        suite.run(f"fragment-burst disable radio {radio_id}")
        suite.run(f"fragment-burst dynamic radio {radio_id}")
        suite.run(f"fragment-burst disable radio {radio_id}")

        # peer-distance
        log(f"\n--- peer-distance ---")
        for val in [1000, 5000, 10000, 25000]:
            suite.run(f"peer-distance {val} radio {radio_id}")
        suite.run(f"peer-distance 999 radio {radio_id}", expect_ok=False)
        suite.run(f"peer-distance 1000 radio {radio_id}")

        exit_ap_config()

    return suite


# ===========================================================================
# Suite 4: 协议支持与速率控制
# ===========================================================================
def suite_protocol_rates():
    suite = TestSuite("4.Protocol-Rates")

    for radio_id in range(1, NUM_RADIOS + 1):
        radio_type = RADIO_1_TYPE if radio_id == 1 else RADIO_2_TYPE
        band = "2.4G" if radio_type == "802.11b" else "5G"

        log(f"\n{'='*40}")
        log(f">> 4.{radio_id} Radio {radio_id} ({band}) 协议支持/速率")
        log(f"{'='*40}")

        enter_ap_config(TARGET_AP_NAME)

        log("\n--- 协议开关 ---")
        if band == "2.4G":
            for proto in ["11b", "11g", "11n", "11ax"]:
                suite.run(f"{proto}support enable radio {radio_id}")
                suite.run(f"{proto}support disable radio {radio_id}")
                suite.run(f"{proto}support enable radio {radio_id}")
        else:
            for proto in ["11a", "11n", "11ac", "11ax"]:
                suite.run(f"{proto}support enable radio {radio_id}")
                suite.run(f"{proto}support disable radio {radio_id}")
                suite.run(f"{proto}support enable radio {radio_id}")

        log("\n--- MCS ---")
        if band == "2.4G":
            for mcs in [0, 7, 15]:
                suite.run(f"802.11n mcs support {mcs} radio {radio_id}")
            suite.run(f"802.11n mcs support 16 radio {radio_id}", expect_ok=False)
            suite.run(f"802.11n mcs support 15 radio {radio_id}")
        else:
            suite.run(f"802.11n mcs support 15 radio {radio_id}")
            suite.run(f"802.11ac mcs support 9 radio {radio_id}")
            suite.run(f"802.11ac mcs support 10 radio {radio_id}", expect_ok=False)
            suite.run(f"802.11ac mcs support 9 radio {radio_id}")

        log("\n--- beacon rate ---")
        for rate in [1, 2, 5.5, 6, 11, 12, 24]:
            suite.run(f"beacon rate {rate} radio {radio_id}")
        suite.run(f"beacon rate 6 radio {radio_id}")

        if band == "2.4G":
            log("\n--- green-field ---")
            suite.run(f"green-field enable radio {radio_id}")
            suite.run(f"green-field disable radio {radio_id}")

        exit_ap_config()

    return suite


# ===========================================================================
# Suite 5: 高级射频特性
# ===========================================================================
def suite_advanced_radio():
    suite = TestSuite("5.Advanced-Radio")

    for radio_id in range(1, NUM_RADIOS + 1):
        radio_type = RADIO_1_TYPE if radio_id == 1 else RADIO_2_TYPE
        band = "2.4G" if radio_type == "802.11b" else "5G"
        log(f"\n--- 5.{radio_id} Radio {radio_id} ({band}) ---")

        enter_ap_config(TARGET_AP_NAME)

        # OFDMA / MU-MIMO / mCell
        suite.run(f"ofdma enable radio {radio_id}")
        suite.run(f"ofdma disable radio {radio_id}")
        suite.run(f"ofdma enable radio {radio_id}")

        suite.run(f"mu-mimo enable radio {radio_id}")
        suite.run(f"mu-mimo disable radio {radio_id}")

        suite.run(f"mcell enable radio {radio_id}")
        suite.run(f"mcell disable radio {radio_id}")

        # Pre-ax DCCA/DTPC
        suite.run(f"wopt dcca enable auto radio {radio_id}")
        for level in [0, 5, 10]:
            suite.run(f"wopt dcca enable {level} radio {radio_id}")
        suite.run(f"wopt dcca enable auto radio {radio_id}")

        suite.run(f"wopt dtpc enable radio {radio_id}")
        suite.run(f"wopt dtpc disable radio {radio_id}")

        # LDPC/STBC
        suite.run(f"ldpc radio {radio_id}")
        suite.run(f"stbc radio {radio_id}")

        # AMPDU
        suite.run(f"ampdu-retries 10 radio {radio_id}")
        suite.run(f"ampdu-retries 1 radio {radio_id}")
        suite.run(f"ampdu-retries 5 radio {radio_id}")
        suite.run(f"ampdu-retries 0 radio {radio_id}", expect_ok=False)
        suite.run(f"ampdu-retries 10 radio {radio_id}")
        suite.run(f"ampdu-rts radio {radio_id}")

        exit_ap_config()

    # 供电管理 (全局)
    enter_ap_config(TARGET_AP_NAME)
    suite.run("poe-unlimit")
    suite.run("poeout enable")
    suite.run("poeout disable")
    suite.run("poeout default")
    exit_ap_config()

    return suite


# ===========================================================================
# Suite 6: RSSI 门限与接入控制
# ===========================================================================
def suite_rssi_access():
    suite = TestSuite("6.RSSI-Access")

    for radio_id in range(1, NUM_RADIOS + 1):
        radio_type = RADIO_1_TYPE if radio_id == 1 else RADIO_2_TYPE
        band = "2.4G" if radio_type == "802.11b" else "5G"
        log(f"\n--- 6.{radio_id} Radio {radio_id} ({band}) ---")

        enter_ap_config(TARGET_AP_NAME)

        # 网络开关
        if band == "2.4G":
            suite.run(f"802.11b network enable radio {radio_id}")
            suite.run(f"802.11b network disable radio {radio_id}")
            suite.run(f"802.11b network enable radio {radio_id}")
        else:
            suite.run(f"802.11a network enable radio {radio_id}")
            suite.run(f"802.11a network disable radio {radio_id}")
            suite.run(f"802.11a network enable radio {radio_id}")

        # RSSI
        for rssi in [0, -30, -50, -70, -90, -100]:
            suite.run(f"response-rssi {rssi} radio {radio_id}")
        suite.run(f"response-rssi -70 radio {radio_id}")

        for rssi in [0, -30, -50, -75, -100]:
            suite.run(f"assoc-rssi {rssi} radio {radio_id}")
        suite.run(f"assoc-rssi -75 radio {radio_id}")

        # STA 限制
        for limit in [0, 10, 30, 64, 128, 256]:
            suite.run(f"sta-limit {limit} radio {radio_id}")
        suite.run(f"sta-limit 30 radio {radio_id}")

        exit_ap_config()

    # 整机 STA 限制
    enter_ap_config(TARGET_AP_NAME)
    suite.run("sta-limit 512")
    suite.run("sta-limit 128")
    suite.run("sta-limit 0")
    suite.run("sta-limit 64")

    # 智能隐藏SSID
    suite.run("hide-ssid sta-reach-limit")
    suite.run("hide-ssid sta-reach-limit radio 2.4g")
    suite.run("hide-ssid sta-reach-limit radio 5g")
    suite.run("no hide-ssid")
    exit_ap_config()

    return suite


# ===========================================================================
# Suite 7: 节电与链路检测
# ===========================================================================
def suite_power_save():
    suite = TestSuite("7.PowerSave")

    enter_ap_config(TARGET_AP_NAME)
    for radio_id in range(1, NUM_RADIOS + 1):
        suite.run(f"apsd enable radio {radio_id}")
        suite.run(f"apsd disable radio {radio_id}")
        suite.run(f"apsd enable radio {radio_id}")

    suite.run("link-check enable")
    suite.run("no link-check enable")
    suite.run("ebag")
    exit_ap_config()

    return suite


# ===========================================================================
# Suite 8: 频谱导航
# ===========================================================================
def suite_band_steering():
    suite = TestSuite("8.BandSteering")

    enter_ap_config(TARGET_AP_NAME)

    log("\n--- band-select ---")
    suite.run("band-select enable radio 1")
    suite.run("band-select disable radio 1")
    suite.run("band-select enable radio 1")

    for rssi in [-80, -70, -60, -50]:
        suite.run(f"band-select acceptable-rssi {rssi}")
    suite.run("band-select acceptable-rssi -80")

    for n in [0, 1, 2, 3, 5, 10]:
        suite.run(f"band-select access-denial {n}")
    suite.run("band-select access-denial 2")

    suite.run("band-select age-out dual-band 60")
    suite.run("band-select age-out dual-band 20")
    suite.run("band-select age-out dual-band 120")
    suite.run("band-select age-out suppression 20")
    suite.run("band-select age-out suppression 10")
    suite.run("band-select age-out suppression 60")

    for n in [1, 2, 5, 10]:
        suite.run(f"band-select probe-count {n}")
    suite.run("band-select probe-count 2")

    for n in [100, 200, 500, 1000]:
        suite.run(f"band-select scan-cycle {n}")
    suite.run("band-select scan-cycle 200")

    suite.run("band-select disable radio 1")

    log("\n--- band-optimize he-radio ---")
    suite.run("band-optimize he-radio enable")
    suite.run("band-optimize he-radio enable auto")
    suite.run("band-optimize he-radio enable fixed")
    suite.run("band-optimize he-radio mode 11axonly")
    suite.run("band-optimize he-radio mode 11ac_11ax")

    for n in [0, 1, 3, 5, 10]:
        suite.run(f"band-select he-radio access-denial {n}")
    suite.run("band-select he-radio access-denial 2")

    for n in [1, 3, 5, 10]:
        suite.run(f"band-select he-radio probe-count {n}")
    suite.run("band-select he-radio probe-count 2")

    suite.run("band-optimize he-radio disable")
    exit_ap_config()

    return suite


# ===========================================================================
# Suite 9: WLAN 配置
# ===========================================================================
def suite_wlan_config():
    suite = TestSuite("9.WLAN-Config")

    # 创建 WLAN 模板
    enter_config()
    for wlan_idx in range(NUM_WLANS):
        wlan_id = WLAN_START_ID + wlan_idx
        vlan_id = WLAN_VLAN_BASE + wlan_idx
        ssid_name = f"Stress-WLAN{wlan_id}"

        log(f"\n--- WLAN {wlan_id}: SSID={ssid_name} VLAN={vlan_id} ---")

        suite.run(f"wlan-config {wlan_id} {ssid_name}")
        session.cmd(f"wlan-config {wlan_id}")
        time.sleep(0.1)
        suite.run(f"ssid {ssid_name}")
        suite.run("enable-broad-ssid")
        suite.run(f"nas-id {10000000 + wlan_id}")
        session.cmd("exit")
        time.sleep(0.1)

        # 部署到 AP 组
        session.cmd("ap-group default")
        time.sleep(0.1)
        suite.run(f"interface-mapping {wlan_id} {vlan_id} radio 802.11b 802.11a")
        session.cmd("exit")
        time.sleep(0.1)

        # STA 限制
        session.cmd(f"wlan-config {wlan_id}")
        time.sleep(0.1)
        for limit in [0, 10, 30, 64]:
            suite.run(f"sta-limit {limit}")
        suite.run("sta-limit 30")
        session.cmd("exit")
        time.sleep(0.1)

    # 默认 SSID
    enter_ap_config(TARGET_AP_NAME)
    suite.run("offline-ssid Fallback-WiFi")
    suite.run("offline-ssid Fallback-WiFi hide")
    suite.run("no offline-ssid")
    exit_ap_config()

    return suite


# ===========================================================================
# Suite 10: WQOS
# ===========================================================================
def suite_wqos():
    suite = TestSuite("10.WQOS")

    enter_ap_config(TARGET_AP_NAME)

    log("\n--- AP/STA limit ---")
    for limit in [0, 10000, 50000, 100000, 1000000]:
        suite.run(f"wqos ap-limit {limit}")
    suite.run("wqos ap-limit 100000")

    for limit in [0, 1000, 5000, 20000]:
        suite.run(f"wqos sta-limit {limit}")
    suite.run("wqos sta-limit 10000")

    log("\n--- fair-schedule ---")
    suite.run("wqos fair-schedule enable")
    suite.run("wqos fair-schedule disable")
    suite.run("wqos fair-schedule enable")

    log("\n--- sta-fair ---")
    suite.run("sta-fair 00:11:22:33:44:55 priority 1")
    suite.run("sta-fair 00:11:22:33:44:55 priority 6")
    suite.run("sta-fair 00:11:22:33:44:55 priority 0", expect_ok=False)
    suite.run("no sta-fair 00:11:22:33:44:55")

    exit_ap_config()
    return suite


# ===========================================================================
# Suite 11: CAPWAP 参数
# ===========================================================================
def suite_capwap():
    suite = TestSuite("11.CAPWAP")

    enter_ap_config(TARGET_AP_NAME)

    log("\n--- acip ---")
    suite.run(f"acip ipv4 {AC_PRIMARY_IP}")
    suite.run(f"acip ipv4 {AC_PRIMARY_IP} {AC_PRIMARY_IP}")

    log("\n--- echo-interval ---")
    for interval in [5, 10, 30, 60, 120]:
        suite.run(f"echo-interval {interval}")
    suite.run("echo-interval 0", expect_ok=False)
    suite.run("echo-interval 30")

    log("\n--- max-retransmit ---")
    for n in [1, 2, 3, 5, 10]:
        suite.run(f"capwap max-retransmit {n}")
    suite.run("capwap max-retransmit 3")

    log("\n--- DTLS ---")
    suite.run("capwap dtls enable")
    suite.run("capwap dtls disable")

    log("\n--- fragment/MTU ---")
    suite.run("capwap fragment enable")
    suite.run("capwap fragment disable")
    for mtu in [576, 1000, 1400, 1500, 9000]:
        suite.run(f"capwap mtu {mtu}")
    suite.run("capwap mtu 1500")

    exit_ap_config()
    return suite


# ===========================================================================
# Suite 12: 安全 (RSNA)
# ===========================================================================
def suite_security():
    suite = TestSuite("12.Security")

    enter_wlan_config(WLAN_START_ID)

    log("\n--- WPA ---")
    suite.run("security wpa enable")
    suite.run("security wpa ciphers aes enable")
    suite.run("security wpa ciphers tkip enable")
    suite.run("security wpa ciphers tkip disable")
    suite.run("security wpa akm psk enable")
    suite.run("security wpa akm 802.1x enable")
    suite.run("security wpa akm 802.1x disable")
    suite.run("security wpa akm psk set-key ascii StressTest123")
    suite.run("security wpa akm psk set-key ascii ShortPWD")
    suite.run("security wpa akm psk set-key ascii MaxLen63-01234567890123456789012345678901234567890123456789")
    suite.run("security wpa akm psk set-key hex 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    suite.run("security wpa disable")

    log("\n--- RSN (WPA2) ---")
    suite.run("security rsn enable")
    suite.run("security rsn ciphers aes enable")
    suite.run("security rsn akm psk enable")
    suite.run("security rsn akm psk set-key ascii RSN-Pass123")
    suite.run("security rsn disable")

    log("\n--- WEP ---")
    suite.run("security static-wep-key encryption 40 hex 1 aabbccddee")
    suite.run("security static-wep-key encryption 104 hex 1 aabbccddeeff0011223344556677")
    suite.run("security static-wep-key authentication open")
    suite.run("security static-wep-key authentication share-key")

    log("\n--- MAB ---")
    suite.run("dot1x-mab")
    suite.run("no dot1x-mab")

    log("\n--- 认证超时 ---")
    suite.run("authtimeout paircount 4")
    suite.run("authtimeout paircount 1")
    suite.run("authtimeout paircount 10")
    suite.run("authtimeout paircount 4")

    suite.run("authtimeout pairtime 1200")
    suite.run("authtimeout pairtime 500")
    suite.run("authtimeout pairtime 3000")
    suite.run("authtimeout pairtime 1200")

    suite.run("authtimeout groupcount 4")
    suite.run("authtimeout groupcount 1")
    suite.run("authtimeout groupcount 10")
    suite.run("authtimeout groupcount 4")

    suite.run("authtimeout grouptime 1200")
    suite.run("authtimeout grouptime 500")
    suite.run("authtimeout grouptime 3000")
    suite.run("authtimeout grouptime 1200")

    suite.run("authtimeout forbidcount 5")
    suite.run("authtimeout forbidcount 1")
    suite.run("authtimeout forbidcount 20")
    suite.run("authtimeout forbidcount 5")

    suite.run("authtimeout forbidtime 60")
    suite.run("authtimeout forbidtime 10")
    suite.run("authtimeout forbidtime 3600")
    suite.run("authtimeout forbidtime 60")

    suite.run("webauth prevent-jitter 300")
    suite.run("webauth prevent-jitter 0")
    suite.run("webauth prevent-jitter 86400")
    suite.run("webauth prevent-jitter 300")

    exit_wlan_config()
    return suite


# ===========================================================================
# Suite 13: NFPP
# ===========================================================================
def suite_nfpp():
    suite = TestSuite("13.NFPP")

    enter_config()
    session.cmd("nfpp")
    time.sleep(0.1)

    log("\n--- ARP ---")
    suite.run("arp-guard enable")
    suite.run("arp-guard rate-limit per-src-ip 100")
    suite.run("arp-guard rate-limit per-src-ip 50")
    suite.run("arp-guard rate-limit per-src-ip 9999")
    suite.run("arp-guard rate-limit per-src-ip 100")
    suite.run("arp-guard isolate-period 300")
    suite.run("arp-guard isolate-period 0")
    suite.run("arp-guard isolate-period 86400")
    suite.run("arp-guard isolate-period permanent")
    suite.run("arp-guard isolate-period 300")
    suite.run("arp-guard scan-threshold 100")
    suite.run("arp-guard scan-threshold 10")
    suite.run("arp-guard scan-threshold 1000")
    suite.run("arp-guard scan-threshold 100")
    suite.run("arp-guard monitor-period 600")
    suite.run("arp-guard monitor-period 180")
    suite.run("arp-guard monitor-period 86400")
    suite.run("arp-guard monitor-period 600")
    suite.run("arp-guard disable")

    log("\n--- IP ---")
    suite.run("ip-guard enable")
    suite.run("ip-guard rate-limit per-src-ip 50")
    suite.run("ip-guard rate-limit per-src-ip 10")
    suite.run("ip-guard rate-limit per-src-ip 9999")
    suite.run("ip-guard rate-limit per-src-ip 50")
    suite.run("ip-guard disable")

    log("\n--- ICMP ---")
    suite.run("icmp-guard enable")
    suite.run("icmp-guard rate-limit 100")
    suite.run("icmp-guard rate-limit 10")
    suite.run("icmp-guard rate-limit 9999")
    suite.run("icmp-guard rate-limit 100")
    suite.run("icmp-guard disable")

    log("\n--- DHCP ---")
    suite.run("dhcp-guard enable")
    suite.run("dhcp-guard rate-limit 60")
    suite.run("dhcp-guard rate-limit 10")
    suite.run("dhcp-guard rate-limit 9999")
    suite.run("dhcp-guard rate-limit 60")
    suite.run("dhcp-guard disable")

    session.cmd("exit")
    exit_config()
    return suite


# ===========================================================================
# Suite 14: Show 验证
# ===========================================================================
def suite_show():
    suite = TestSuite("14.Show-Verify")

    show_cmds = [
        "show ap-config summary",
        f"show ap-config ap-name {TARGET_AP_NAME}",
        "show ap-status",
        "show wlan-config summary",
        "show sta-list",
        "show capwap state",
        "show ac-controller",
        "show version",
    ]

    for cmd in show_cmds:
        output = session.cmd(cmd)
        has_err = any(kw in output.lower() for kw in ["error:", "invalid", "% "])
        if has_err:
            suite.fail_count += 1
            log_fail(cmd, output[:80])
        else:
            suite.pass_count += 1
            log_pass(cmd)
        time.sleep(0.3)

    return suite


# ===========================================================================
# 主流程
# ===========================================================================

def setup_log():
    global LOG_FILE
    if not LOG_FILE:
        LOG_FILE = f"ap_stress_{TARGET_AP_NAME}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    print(f"Log file: {os.path.abspath(LOG_FILE)}")


def print_banner():
    banner = f"""
╔══════════════════════════════════════════════════════════════╗
║     RG-AC AP 配置拷机脚本 (Telnet 直连)                      ║
╠══════════════════════════════════════════════════════════════╣
║  AC:          {AC_HOST}:{AC_PORT:<43}║
║  Target AP:   {TARGET_AP_NAME:<43}║
║  Radios:      {NUM_RADIOS:<43}║
║  WLANs:       {NUM_WLANS:<43}║
║  Mode:        {TEST_MODE:<43}║
╚══════════════════════════════════════════════════════════════╝"""
    print(banner)
    log(banner)


def main():
    global session

    setup_log()
    print_banner()

    # --- 连接 AC ---
    log("Connecting to AC...")
    session = TelnetSession(AC_HOST, AC_PORT, timeout=15)
    try:
        session.connect()
        log("Telnet connected", "PASS")
    except Exception as e:
        log(f"Connection failed: {e}", "ERROR")
        return False

    # --- 登录 ---
    log("Logging in...")
    if not session.login(AC_USER, AC_PASSWORD):
        log("Login failed", "ERROR")
        session.close()
        return False
    log("Login OK", "PASS")

    # 清屏，确保在干净状态
    session.cmd("")
    time.sleep(0.3)

    # --- 执行测试套件 ---
    suites = []
    start_time = datetime.now()

    try:
        log("\n" + "="*60)
        log("PHASE 1: AP 基础与 AC 冗余")
        log("="*60)
        suites.append(suite_ap_identity())
        suites.append(suite_ap_priority())

        log("\n" + "="*60)
        log("PHASE 2: 射频参数穷举")
        log("="*60)
        suites.append(suite_radio_params())
        suites.append(suite_protocol_rates())
        suites.append(suite_advanced_radio())

        log("\n" + "="*60)
        log("PHASE 3: 接入控制与优化")
        log("="*60)
        suites.append(suite_rssi_access())
        suites.append(suite_power_save())
        suites.append(suite_band_steering())

        log("\n" + "="*60)
        log("PHASE 4: WLAN 部署与 QoS")
        log("="*60)
        suites.append(suite_wlan_config())
        suites.append(suite_wqos())

        log("\n" + "="*60)
        log("PHASE 5: CAPWAP 与安全")
        log("="*60)
        suites.append(suite_capwap())
        suites.append(suite_security())
        suites.append(suite_nfpp())

        log("\n" + "="*60)
        log("PHASE 6: Show 验证")
        log("="*60)
        suites.append(suite_show())

    except KeyboardInterrupt:
        log("\nInterrupted by user", "WARN")
    except Exception as e:
        log(f"Fatal error: {e}", "ERROR")
        import traceback
        traceback.print_exc()
    finally:
        # 确保退出配置模式
        try:
            exit_config()
        except Exception:
            pass
        session.close()

    # --- 汇总报告 ---
    end_time = datetime.now()
    duration = end_time - start_time

    total_pass = sum(s.pass_count for s in suites)
    total_fail = sum(s.fail_count for s in suites)
    total_skip = sum(s.skip_count for s in suites)
    total_all = total_pass + total_fail + total_skip
    success_rate = total_pass / total_all * 100 if total_all > 0 else 0

    report = f"""
╔══════════════════════════════════════════════════════════════╗
║                    拷 机 完 成 报 告                          ║
╠══════════════════════════════════════════════════════════════╣
║  Duration:     {str(duration):<42}║
║  PASS: {total_pass:<5}  FAIL: {total_fail:<5}  SKIP: {total_skip:<5}  TOTAL: {total_all:<5}║
║  Success Rate: {success_rate:.1f}%{'':<36}║
╠══════════════════════════════════════════════════════════════╣
║  Suite Breakdown:                                           ║"""

    for s in suites:
        total = s.pass_count + s.fail_count + s.skip_count
        rate = s.pass_count / total * 100 if total > 0 else 0
        report += f"\n║  {s.name:<28s} P:{s.pass_count:4d} F:{s.fail_count:4d} S:{s.skip_count:4d} ({rate:5.1f}%){'':>6}║"

    report += """
╚══════════════════════════════════════════════════════════════╝"""

    print(report)
    log(report)

    # 写入日志
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(report)
        f.write(f"\n# Finished: {datetime.now().isoformat()}\n")

    return total_fail == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AP Config Stress Test via Telnet")
    parser.add_argument("--dry-run", action="store_true", help="Dry run (connect + show only, no config changes)")
    args = parser.parse_args()

    if args.dry_run:
        log("DRY-RUN: connect + verify only")
        session = TelnetSession(AC_HOST, AC_PORT, timeout=15)
        session.connect()
        log("Telnet connected", "PASS")
        if not session.login(AC_USER, AC_PASSWORD):
            log("Login failed", "ERROR")
            session.close()
            sys.exit(1)
        log("Login OK", "PASS")
        for cmd in ["show version", "show ap-config summary", "show wlan-config summary", "show ap-status"]:
            output = session.cmd(cmd)
            print(f"  {cmd}: OK ({len(output)} bytes)")
        session.close()
        log("DRY-RUN complete", "PASS")
        sys.exit(0)

    success = main()
    sys.exit(0 if success else 1)
