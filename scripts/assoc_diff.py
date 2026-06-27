#!/usr/bin/env python3
"""
==========================================================================
802.11 关联协商报文对比分析工具 (tshark 全字段解析版)
用法: python3 assoc_diff.py <pcap_file_1> <pcap_file_2> [-o report.html]
==========================================================================
基于 tshark -V 完整解码 802.11 管理帧的所有 IE 字段，逐字段对比差异。
不再依赖 scapy 的有限 IE 解析。
==========================================================================
"""

import sys
import os
import re
import argparse
import subprocess
import tempfile
from collections import defaultdict
from datetime import datetime


# ===========================================================================
# tshark 管理帧完整字段解析
# ===========================================================================

FRAME_START_RE = re.compile(r'^Frame (\d+):')
TYPE_SUBTYPE_RE = re.compile(r'Type/Subtype:\s*(.+?)\s*\((0x[0-9a-fA-F]+)\)')
TAG_NUMBER_RE = re.compile(r'Tag Number:\s*(.+?)\s*\((\d+)\)')
BITMAP_FIELD_RE = re.compile(r'^[.01\s]+=\s*(.+?):\s*(.*)')
KV_FIELD_RE = re.compile(r'^(\S[^:]*?)\s*:\s*(.*)')


def run_tshark_verbose(filepath, filter_mac=""):
    """运行 tshark -V 获取管理帧完整解码文本。
    
    返回: tshark stdout+stderr 文本，或 None
    """
    read_filter = "wlan.fc.type == 0"
    if filter_mac:
        mac = filter_mac.strip().lower()
        # tshark read filter: 匹配该MAC出现的任何地址字段
        read_filter += (
            f" && (wlan.da=={mac} || wlan.sa=={mac} "
            f"|| wlan.ta=={mac} || wlan.ra=={mac})"
        )

    cmd = ["tshark", "-r", filepath, "-2", "-R", read_filter, "-V"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        # tshark -V 输出在 stderr
        return r.stderr + r.stdout
    except subprocess.TimeoutExpired:
        print(f"  ERROR: tshark timeout on {filepath}")
        return None
    except FileNotFoundError:
        print("  ERROR: tshark not found! Install: sudo apt install tshark")
        return None


def parse_tshark_verbose(text):
    """解析 tshark -V 输出，提取帧类型和每个 IE 的完整解码字段。
    
    返回: [{
        "frame_num": int,
        "type": "Probe Response",
        "type_hex": "0x0005",
        "ies": [{
            "id": 0,
            "name": "SSID parameter set",
            "fields": {"SSID": "RG-AP680C-V2-2.4G", ...}
        }, ...]
    }, ...]
    """
    frames = []
    current_frame = None
    current_ie = None
    ie_indent = 0
    in_mgmt_body = False
    lines = text.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i]

        # ── Frame 边界 ──
        m = FRAME_START_RE.match(line)
        if m:
            fnum = int(m.group(1))
            # 保存前一帧
            if current_frame is not None:
                if current_ie:
                    current_frame["ies"].append(current_ie)
                    current_ie = None
                frames.append(current_frame)
            # 开始新帧
            current_frame = {"frame_num": fnum, "ies": []}
            current_ie = None
            in_mgmt_body = False
            i += 1
            continue

        if current_frame is None:
            i += 1
            continue

        # ── 帧类型 ──
        m = TYPE_SUBTYPE_RE.search(line)
        if m:
            current_frame["type"] = m.group(1).strip()
            current_frame["type_hex"] = m.group(2)
            i += 1
            continue

        # ── 管理帧体入口 ──
        if "IEEE 802.11 Wireless Management" in line:
            in_mgmt_body = True
            i += 1
            continue

        if not in_mgmt_body:
            i += 1
            continue

        # ── Fixed parameters 节 (Action/Auth/Deauth 等帧的固定字段) ──
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if stripped.startswith("Fixed parameters"):
            # 创建伪 IE 容纳固定参数字段
            if current_ie:
                current_frame["ies"].append(current_ie)
            current_ie = {"indent": indent, "fields": {}, "id": -1, "name": "Fixed parameters"}
            ie_indent = indent
            i += 1
            continue

        # ── Tagged parameters 节边界 ──
        if stripped.startswith("Tagged parameters"):
            # 结束 Fixed parameters (如果有)
            if current_ie and current_ie.get("id") == -1:
                current_frame["ies"].append(current_ie)
                current_ie = None
            i += 1
            continue

        # ── IE (Tag) 检测 ──
        if stripped.startswith("Tag:") or stripped.startswith("Ext Tag:"):
            # 保存上一个 IE
            if current_ie:
                current_frame["ies"].append(current_ie)

            current_ie = {"indent": indent, "fields": {}}
            ie_indent = indent
            # Tag: 行本身作为显示名
            current_ie["tag_display"] = stripped
            i += 1
            continue

        # ── Tag Number: 行 (提取 IE ID 和名称) ──
        if stripped.startswith("Tag Number:") and current_ie:
            m = TAG_NUMBER_RE.search(stripped)
            if m:
                current_ie["name"] = m.group(1).strip()
                current_ie["id"] = int(m.group(2))
            i += 1
            continue

        # ── 子字段 (缩进大于 IE 起始行) ──
        if current_ie and indent > ie_indent and stripped:
            # 跳过 Tag length 和纯元数据行
            if stripped.startswith("Tag length:") or stripped.startswith("Tag interpretation:"):
                i += 1
                continue

            # 位图子字段: ".... .... = Name: value"
            bm = BITMAP_FIELD_RE.match(stripped)
            if bm:
                key = bm.group(1).strip()
                val = bm.group(2).strip()
                if key and not key.startswith("0x"):
                    current_ie["fields"][key] = val
                i += 1
                continue

            # 普通 K: V 子字段
            kv = KV_FIELD_RE.match(stripped)
            if kv:
                key = kv.group(1).strip()
                val = kv.group(2).strip()
                # 跳过纯十六进制/二进制缩写
                if key and not re.match(r'^[.01\s]+$', key):
                    current_ie["fields"][key] = val
            i += 1
            continue

        i += 1

    # 最后一帧
    if current_ie:
        current_frame["ies"].append(current_ie)
    if current_frame is not None:
        frames.append(current_frame)

    return frames


# ===========================================================================
# 帧分组与匹配
# ===========================================================================

# Action 帧子类型数据库
ACTION_CATEGORIES = {
    0: "Spectrum Management", 1: "QoS", 3: "Block ACK", 4: "Public Action",
    5: "Radio Measurement (11k)", 6: "Fast BSS Transition (11r)",
    7: "HT Action", 8: "SA Query",
    10: "WNM (11v)", 12: "TDLS", 19: "VHT Action",
    126: "Vendor Specific (Protected)", 127: "Vendor Specific",
}


def get_frame_label(frame):
    """获取帧的显示标签。Action 帧按 Action code 作为独立帧类型。"""
    ftype = frame.get("type", "Unknown")
    if ftype == "Action":
        for ie in frame.get("ies", []):
            fields = ie.get("fields", {})
            act_val = fields.get("Action code", "")
            if act_val:
                # tshark 格式: "Delete Block Ack (0x02)" → 提取动作名
                act_name = re.sub(r'\s*\(.*', '', str(act_val)).strip()
                if act_name:
                    return f"Action: {act_name}"
    return ftype


# 帧类型报告排序权重
FRAME_REPORT_ORDER = [
    "Probe Request", "Probe Response",
    "Authentication",
    "Association Request", "Association Response",
    "Reassociation Request", "Reassociation Response",
]


def frame_sort_key(ftype_name):
    for i, base in enumerate(FRAME_REPORT_ORDER):
        if ftype_name.startswith(base):
            return i
    if ftype_name.startswith("Action"):
        return 100
    return 99


def is_broadcast_probe(frame):
    """判断是否为广播 Probe Request (SSID为空)。"""
    if frame.get("type") != "Probe Request":
        return False
    for ie in frame.get("ies", []):
        if ie.get("id") == 0:
            ssid = ie.get("fields", {}).get("SSID", "")
            # tshark uses <MISSING> or empty for wildcard SSID
            return not ssid or ssid in ('""', "<MISSING>", "Wildcard (Broadcast)")
    # 没有 SSID IE → 广播
    return True


def group_frames_tshark(frames):
    """按帧标签分组 (tshark 解析后的帧)。"""
    groups = defaultdict(list)
    for f in frames:
        label = get_frame_label(f)
        if label:
            groups[label].append(f)
    return dict(groups)


def match_frames(frames_a, frames_b):
    """匹配两组的帧 —— 按类型和顺序。过滤广播 Probe Request。"""
    pairs = []
    all_types = sorted(
        set(list(frames_a.keys()) + list(frames_b.keys())),
        key=frame_sort_key
    )
    for ftype_name in all_types:
        list_a = list(frames_a.get(ftype_name, []))
        list_b = list(frames_b.get(ftype_name, []))

        # 过滤广播 Probe Request
        if ftype_name == "Probe Request":
            unicast_a = [f for f in list_a if not is_broadcast_probe(f)]
            unicast_b = [f for f in list_b if not is_broadcast_probe(f)]
            bc_a = len(list_a) - len(unicast_a)
            bc_b = len(list_b) - len(unicast_b)
            if bc_a or bc_b:
                print(f"  Broadcast Probe Request filtered: A {bc_a}, B {bc_b}")
            list_a, list_b = unicast_a, unicast_b

        matched = min(len(list_a), len(list_b))
        for i in range(matched):
            pairs.append((ftype_name, list_a[i], list_b[i]))
        for i in range(matched, len(list_a)):
            pairs.append((ftype_name, list_a[i], None))
        for i in range(matched, len(list_b)):
            pairs.append((ftype_name, None, list_b[i]))

    return pairs


# ===========================================================================
# IE 字段对比
# ===========================================================================

def compare_ies_tshark(ies_a, ies_b):
    """对比两个帧的 IE 列表 (tshark 解析后)，返回差异列表。
    
    Returns: [{
        "ie_id": int, "name": str,
        "type": "different" | "missing_in_a" | "missing_in_b" | "identical",
        "fields_a": {...}, "fields_b": {...},
        "subfield_diffs": [{"field": str, "value_a": str, "value_b": str}, ...]
    }, ...]
    """
    # Build maps: {ie_id: ie_dict}
    map_a = {}
    for ie in ies_a:
        eid = ie.get("id")
        if eid is not None:
            map_a[eid] = ie
    map_b = {}
    for ie in ies_b:
        eid = ie.get("id")
        if eid is not None:
            map_b[eid] = ie

    all_ids = sorted(set(list(map_a.keys()) + list(map_b.keys())))
    diffs = []

    for eid in all_ids:
        ie_a = map_a.get(eid)
        ie_b = map_b.get(eid)
        name = ""
        if ie_a:
            name = ie_a.get("name", f"IE-{eid}")
        elif ie_b:
            name = ie_b.get("name", f"IE-{eid}")

        if ie_a and not ie_b:
            diffs.append({
                "ie_id": eid, "name": name,
                "type": "missing_in_b",
                "fields_a": ie_a.get("fields", {}),
                "fields_b": {},
                "subfield_diffs": [
                    {"field": k, "value_a": str(v), "value_b": "—"}
                    for k, v in sorted(ie_a.get("fields", {}).items())
                ]
            })
        elif not ie_a and ie_b:
            diffs.append({
                "ie_id": eid, "name": name,
                "type": "missing_in_a",
                "fields_a": {},
                "fields_b": ie_b.get("fields", {}),
                "subfield_diffs": [
                    {"field": k, "value_a": "—", "value_b": str(v)}
                    for k, v in sorted(ie_b.get("fields", {}).items())
                ]
            })
        else:
            fa = ie_a.get("fields", {})
            fb = ie_b.get("fields", {})
            all_keys = sorted(set(list(fa.keys()) + list(fb.keys())))
            sub_diffs = []
            for k in all_keys:
                va = str(fa.get(k, "—"))
                vb = str(fb.get(k, "—"))
                if va != vb:
                    sub_diffs.append({"field": k, "value_a": va, "value_b": vb})

            if sub_diffs:
                diffs.append({
                    "ie_id": eid, "name": name,
                    "type": "different",
                    "fields_a": fa, "fields_b": fb,
                    "subfield_diffs": sub_diffs
                })

    return diffs


# ===========================================================================
# 字段知识库 — 协议用途 & 影响评估
# ===========================================================================

# 子字段名 → (协议用途, 差异影响说明, 网络影响等级: 🔴高 🟡中 🟢低)
FIELD_KNOWLEDGE = {
    # ── HT Capabilities ──
    "LDPC Coding Capability": (
        "LDPC 低密度奇偶校验编码",
        "支持LDPC可提升弱信号下的解码成功率",
        "🟢 弱信号场景下丢包率差异 3-5%"
    ),
    "40MHz": (
        "40MHz 信道带宽支持",
        "40MHz使单流速率翻倍 (150→300Mbps)",
        "🔴 吞吐量差异可达 2 倍"
    ),
    "Short GI": (
        "Short Guard Interval (短保护间隔)",
        "SGI缩短符号间保护间隔，提升约11%速率",
        "🟡 高SNR下吞吐量差异 ~11%"
    ),
    "HT-Delayed BA": (
        "HT 延迟 Block ACK",
        "允许延迟确认提升聚合效率",
        "🟢 影响Block ACK交互延迟"
    ),
    "Max A-MSDU": (
        "最大A-MSDU聚合长度",
        "更长聚合帧减少开销，提升效率",
        "🟡 大包吞吐量差异可达10-20%"
    ),
    "DSSS/CCK 40MHz": (
        "40MHz下DSSS/CCK模式",
        "2.4G 40MHz兼容性标志",
        "🟢 传统设备兼容性"
    ),
    "40MHz Intolerant": (
        "40MHz 不容忍标志",
        "声明40MHz不可用，强制20MHz",
        "🔴 直接限制到20MHz，速率减半"
    ),
    "L-SIG TXOP": (
        "L-SIG TXOP 保护",
        "保护机制防传统设备干扰",
        "🟢 混合环境下的干扰防护"
    ),
    "Max A-MPDU": (
        "最大A-MPDU聚合帧大小",
        "更大聚合帧提升Block ACK效率",
        "🟡 高速率下吞吐量差异 5-10%"
    ),
    "Min MPDU Spacing": (
        "最小MPDU间隔",
        "更小间隔提升聚合密度",
        "🟢 聚合效率微调"
    ),
    "TX MCS Defined": (
        "TX MCS 反馈定义",
        "MCS反馈使速率自适应更精准",
        "🟡 影响速率自适应精度"
    ),
    "TX Unequal Mod": (
        "TX 非均匀调制",
        "多流不同调制方式提升弱流可靠性",
        "🟡 多天线场景下速率差异"
    ),
    "TX Max SS": (
        "最大空间流数",
        "更多空间流 = 更高吞吐量 (1→2流翻倍)",
        "🔴 最大吞吐量差异可达 2 倍"
    ),
    "SMPS": (
        "空间复用省电模式",
        "SMPS关闭部分天线链省电",
        "🟢 影响功耗 vs 速率平衡"
    ),
    "Greenfield": (
        "Greenfield 模式",
        "纯HT环境无传统保护开销",
        "🟢 纯11n环境效率微升"
    ),
    "TX STBC": (
        "发射空时块编码",
        "发射分集提升远距离可靠性",
        "🟡 边缘覆盖可靠性提升"
    ),
    "RX STBC": (
        "接收空时块编码",
        "接收分集提升下行可靠性",
        "🟡 下行边缘覆盖提升"
    ),
    "HTC": (
        "HT Control 字段支持",
        "允许在数据帧携带HT控制信息",
        "🟢 协议灵活性"
    ),

    # ── VHT Capabilities ──
    "Supported Ch Width": (
        "VHT 信道带宽支持",
        "决定最大可用带宽 (80/160MHz)",
        "🔴 80→160MHz 吞吐量翻倍"
    ),
    "Short GI 80MHz": (
        "80MHz 下 Short GI",
        "80MHz带宽+SGI组合提升效率",
        "🟡 80MHz下额外 ~11% 增益"
    ),
    "Short GI 160MHz": (
        "160MHz 下 Short GI",
        "160MHz带宽+SGI组合",
        "🟡 160MHz下额外 ~11% 增益"
    ),
    "SU Beamformer": (
        "单用户波束成形",
        "AP侧波束成形提升定向增益",
        "🟡 中远距离 SNR 提升 2-3dB"
    ),
    "MU Beamformer": (
        "多用户波束成形",
        "同时服务多STA,大幅提升总吞吐",
        "🔴 多用户场景总吞吐差异 30-50%"
    ),
    "VHT MCS": (
        "VHT MCS 支持集",
        "决定最高可用速率等级 (MCS0-9)",
        "🔴 MCS9比MCS7速率高35%"
    ),
    "Max MPDU Length": (
        "VHT 最大MPDU长度",
        "更长帧减少开销",
        "🟡 大数据包效率提升"
    ),
    "VHT Extended NSS": (
        "VHT 扩展空间流数",
        "80+80MHz下额外空间流能力",
        "🟡 特殊场景吞吐量"
    ),
    "Rx MCS Map": (
        "接收MCS映射表",
        "每个空间流支持的接收MCS等级",
        "🔴 直接限制各流最大接收速率"
    ),
    "Tx MCS Map": (
        "发送MCS映射表",
        "每个空间流支持的发送MCS等级",
        "🔴 直接限制各流最大发送速率"
    ),
    "Rx Highest": (
        "最高接收速率",
        "接收方向的理论峰值速率",
        "🟡 理论峰值能力声明"
    ),
    "Tx Highest": (
        "最高发送速率",
        "发送方向的理论峰值速率",
        "🟡 理论峰值能力声明"
    ),

    # ── VHT Operation ──
    "Channel Width": (
        "VHT 操作信道带宽",
        "当前BSS实际使用的信道宽度",
        "🔴 决定实际工作速率上限"
    ),
    "Channel Center": (
        "信道中心频率",
        "80+80模式需要两个中心频率",
        "🟡 影响信道配置正确性"
    ),
    "Basic MCS": (
        "VHT 基础MCS集",
        "BSS内所有STA必须支持的MCS",
        "🟡 影响STA接入门槛"
    ),

    # ── HE Operation ──
    "BSS Color": (
        "BSS 着色标识",
        "用于空间复用，区分同频BSS",
        "🟡 密集部署下减少同频干扰"
    ),
    "Default PE": (
        "默认PE持续时间",
        "节能模式下默认监听周期",
        "🟢 影响STA功耗"
    ),
    "TWT Required": (
        "TWT 目标唤醒时间",
        "调度STA唤醒，显著降低功耗",
        "🟡 IoT/手机场景续航差异明显"
    ),
    "TXOP RTS": (
        "TXOP RTS 阈值",
        "控制RTS/CTS保护触发条件",
        "🟢 隐藏节点处理策略"
    ),
    "Co-hosted BSS": (
        "共址BSS",
        "同一射频多个虚拟AP",
        "🟢 虚拟AP部署管理"
    ),
    "ER SU Disable": (
        "扩展范围单用户禁用",
        "控制远距离覆盖增强模式",
        "🟡 影响边缘覆盖能力"
    ),
    "Basic HE-MCS": (
        "HE 基础MCS集",
        "Wi-Fi 6 强制支持的MCS等级",
        "🟡 影响Wi-Fi6 STA接入兼容性"
    ),

    # ── RSN / Security ──
    "Group Cipher": (
        "组播/广播加密套件",
        "广播帧加密方式",
        "🔴 影响广播通信安全性"
    ),
    "Pairwise Cipher": (
        "单播加密套件",
        "单播数据加密方式 (CCMP/TKIP)",
        "🔴 TKIP已不安全，应使用CCMP"
    ),
    "AKM": (
        "认证密钥管理",
        "身份认证方式 (PSK/802.1X/SAE)",
        "🔴 WPA3-SAE比WPA2-PSK安全性显著提升"
    ),
    "RSN Capabilities": (
        "RSN 能力标志",
        "安全协商能力 (PMF/Pre-Auth等)",
        "🟡 PMF防Deauth攻击"
    ),
    "Group Management Cipher": (
        "组播管理帧加密",
        "保护组管理帧防伪造",
        "🟡 防组播管理帧攻击"
    ),
    "Version": (
        "RSN 版本号",
        "RSN IE 协议版本",
        "🟢 版本兼容性指示"
    ),

    # ── Rates ──
    "Supported Rates": (
        "支持的速率集",
        "STA/AP 声明支持的PHY速率",
        "🔴 速率不匹配会导致关联失败或降速"
    ),

    # ── Power ──
    "Power Constraint": (
        "功率约束",
        "本地最大发射功率限制 (dBm)",
        "🟡 限制覆盖范围"
    ),
    "Power Capability": (
        "功率能力",
        "STA最小/最大发射功率",
        "🟡 影响链路预算和覆盖"
    ),

    # ── ERP ──
    "ERP": (
        "ERP (802.11g) 信息",
        "11g保护模式 (NonERP_Present等)",
        "🟡 影响11b设备共存性能"
    ),
    "Use Protection": (
        "使用保护模式",
        "混合11b/g环境需启用保护",
        "🟡 保护开销降低有效吞吐量 ~30%"
    ),
    "NonERP": (
        "存在非ERP设备",
        "检测到11b设备需降级保护",
        "🟡 触发保护机制,降低吞吐量"
    ),

    # ── Country ──
    "Country": (
        "国家/地区代码",
        "法规域，决定可用信道和功率",
        "🔴 不同国家合法信道不同"
    ),
    "Country Info": (
        "国家信道信息",
        "各信道允许的最大功率",
        "🟡 影响信道可用性和功率上限"
    ),
    "Environment": (
        "环境类型",
        "室内/室外法规限制",
        "🟡 室外通常功率限制更严"
    ),

    # ── Extended Capabilities ──
    "20/40 BSS Coex": (
        "20/40 BSS 共存管理",
        "管理20/40MHz BSS共存,防干扰",
        "🟡 密集部署下减少邻频干扰"
    ),
    "Ext Ch Switch": (
        "扩展信道切换",
        "支持扩展信道切换通告",
        "🟢 信道切换能力"
    ),
    "BSS Transition": (
        "BSS 转换支持",
        "802.11v BSS Transition 管理",
        "🟡 支持网络引导漫游"
    ),
    "WNM": (
        "无线网络管理",
        "802.11v WNM 协议支持",
        "🟡 网络管理/诊断能力"
    ),

    # ── OBSS Scan ──
    "Passive Dwell": (
        "被动扫描驻留时间",
        "OBSS 被动扫描每信道停留",
        "🟢 扫描开销"
    ),
    "Active Dwell": (
        "主动扫描驻留时间",
        "OBSS 主动扫描每信道停留",
        "🟢 扫描开销"
    ),
    "Activity Threshold": (
        "活动门限",
        "触发OBSS扫描的信道利用率门限",
        "🟢 干扰检测灵敏度"
    ),

    # ── WMM / QoS ──
    "WME QoS Info": (
        "WMM QoS Info",
        "QoS能力 (EDCA参数/U-APSD等)",
        "🟡 影响QoS优先级和节能"
    ),
    "U-APSD": (
        "U-APSD 非调度自动节能",
        "允许STA触发式省电传输",
        "🟡 VoIP/省电场景电池续航"
    ),
    "Parameter Set": (
        "WMM 参数集",
        "EDCA各AC队列参数",
        "🟡 影响QoS优先级调度"
    ),
    "QoS Info": (
        "QoS 信息字段",
        "AP/STA QoS能力声明",
        "🟡 QoS功能可用性"
    ),

    # ── Fixed params (Auth) ──
    "Authentication Algorithm": (
        "认证算法",
        "Open System / Shared Key",
        "🔴 Shared Key不安全(已废弃)"
    ),
    "Authentication SEQ": (
        "认证序列号",
        "认证帧序号 (1-4)",
        "🟢 协议状态机"
    ),
    "Status code": (
        "状态码",
        "指示操作结果 (0=成功)",
        "🔴 非0表示关联/认证失败"
    ),
    "Privacy": (
        "隐私/加密使能",
        "Capability Info 中的 Privacy 位",
        "🔴 不匹配导致关联建立失败"
    ),
    "Spectrum Management": (
        "频谱管理能力",
        "支持DFS/TPC等频谱管理",
        "🟡 5GHz DFS信道可用性"
    ),
    "Radio Measurement": (
        "无线测量能力",
        "802.11k 无线资源测量",
        "🟡 影响漫游决策和网络优化"
    ),
    "Capabilities Information": (
        "能力信息字段",
        "STA/AP 基础能力声明位图",
        "🟡 综合能力匹配"
    ),

    # ── Fixed params (Action) ──
    "Category code": (
        "Action 类别",
        "区分Action帧大类 (频谱/QoS/BA等)",
        "🟢 帧路由/分发"
    ),
    "Action code": (
        "Action 子动作",
        "具体操作 (ADDBA/DELBA等)",
        "🔴 决定Block ACK协商行为"
    ),
    "Block Ack Parameters": (
        "Block ACK 参数",
        "BA策略/缓冲区/TID配置",
        "🟡 影响聚合效率和可靠性"
    ),
    "Block Ack Timeout": (
        "Block ACK 超时",
        "BA会话超时时间",
        "🟡 长超时可能导致资源泄漏"
    ),
    "Buffer Size": (
        "Block ACK 缓冲区大小",
        "重排序缓冲区容量",
        "🟡 影响乱序包处理能力"
    ),
    "Block Ack Policy": (
        "Block ACK 策略",
        "立即/延迟BA确认",
        "🟡 延迟BA提升聚合效率"
    ),
    "TID": (
        "流量标识符",
        "QoS流量类别 (0-7)",
        "🟡 不同TID的QoS待遇"
    ),
    "Initiator": (
        "Block ACK 发起方",
        "BA协商发起方标志",
        "🟢 协议角色"
    ),
    "Reason code": (
        "原因码",
        "操作原因 (超时/主动/未知STA等)",
        "🟡 诊断断开原因"
    ),
    "Dialog Token": (
        "Dialog 令牌",
        "匹配请求/响应",
        "🟢 协议匹配"
    ),

    # ── Vendor Specific ──
    "OUI": (
        "厂商OUI标识",
        "标识IE来自哪个厂商",
        "🟢 厂商识别"
    ),
    "Vendor Specific": (
        "厂商私有字段",
        "厂商定义的扩展功能",
        "🟡 功能差异取决于厂商实现"
    ),

    # ── Supported Operating Classes ──
    "Operating Classes": (
        "支持的操作类别",
        "全球信道定义组合",
        "🟡 影响国际漫游兼容性"
    ),

    # ── Neighbor Report ──
    "Neighbor Report": (
        "邻居报告",
        "802.11k 邻居AP信息",
        "🟡 影响漫游候选AP选择"
    ),

    # ── BSS Coexistence ──
    "BSS Coexistence": (
        "20/40 BSS共存",
        "管理40MHz BSS与20MHz BSS共存",
        "🟡 混合带宽环境下的协调"
    ),
    "OBSS Scan": (
        "OBSS扫描参数",
        "控制重叠BSS检测行为",
        "🟢 网络环境感知"
    ),

    # ── HT/VHT Operation ──
    "HT Protection": (
        "HT 保护模式",
        "保护非HT设备共存",
        "🟡 混合环境下吞吐量折损"
    ),
    "RIFS": (
        "RIFS 减少帧间间隔",
        "HT绿野模式下的帧间间隔优化",
        "🟢 微效率提升"
    ),
    "Secondary Channel": (
        "辅信道偏移",
        "40MHz模式的辅信道位置",
        "🟡 影响40MHz信道配置"
    ),
    "STA Channel Width": (
        "STA 信道带宽",
        "STA侧的操作带宽",
        "🟡 实际工作带宽"
    ),
}


def get_field_impact(ie_name, field_name, value_a, value_b):
    """根据字段名匹配知识库，返回 (协议用途, 影响说明, 等级) 或空字符串。"""
    # 精确匹配
    if field_name in FIELD_KNOWLEDGE:
        return FIELD_KNOWLEDGE[field_name]
    # 子串匹配
    for key, info in FIELD_KNOWLEDGE.items():
        if key.lower() in field_name.lower() or field_name.lower() in key.lower():
            return info
    return ("", "", "")

def generate_report(pairs, label_a, label_b, filter_mac="", output_path=None):
    """生成 HTML 对比报告。"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ===== 数据收集 =====
    frame_stats = defaultdict(lambda: {"match": 0, "only_a": 0, "only_b": 0, "diffs": 0})
    frame_uniq_diffs = defaultdict(dict)
    ie_diff_count = 0
    sub_diff_count = 0

    for ftype, pkt_a, pkt_b in pairs:
        ie_diffs = []
        if pkt_a is not None and pkt_b is not None:
            ies_a = pkt_a.get("ies", [])
            ies_b = pkt_b.get("ies", [])
            ie_diffs = compare_ies_tshark(ies_a, ies_b)
            frame_stats[ftype]["match"] += 1
        elif pkt_a is not None:
            frame_stats[ftype]["only_a"] += 1
        elif pkt_b is not None:
            frame_stats[ftype]["only_b"] += 1

        frame_stats[ftype]["diffs"] += len(ie_diffs)

        for d in ie_diffs:
            key = d["ie_id"]
            if key not in frame_uniq_diffs[ftype]:
                frame_uniq_diffs[ftype][key] = {
                    "ie_id": d["ie_id"], "name": d["name"],
                    "diffs": {}, "subfield_diffs": [],
                }
            ex = frame_uniq_diffs[ftype][key]
            ex["diffs"][d["type"]] = True
            # retain first seen subfield_diffs (they should be the same for same ie_id)
            if not ex["subfield_diffs"] and d.get("subfield_diffs"):
                ex["subfield_diffs"] = d["subfield_diffs"]

        ie_diff_count += len(ie_diffs)
        for d in ie_diffs:
            sub_diff_count += len(d.get("subfield_diffs", []))

    # ===== CSS =====
    css = """
    <style>
    body { font-family: -apple-system, 'Segoe UI', sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; color: #222; }
    h1 { font-size: 1.6em; border-bottom: 3px solid #1a73e8; padding-bottom: 8px; color: #1a73e8; }
    h2 { font-size: 1.2em; margin-top: 30px; color: #333; border-bottom: 1px solid #ddd; padding-bottom: 4px; }
    table { border-collapse: collapse; width: 100%; margin: 10px 0; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
    th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; font-size: 0.88em; }
    th { background: #1a73e8; color: #fff; }
    tr:nth-child(even) { background: #f8f9fa; }
    .meta { background: #fff; padding: 15px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,.1); margin-bottom: 20px; }
    .meta td { border: none; padding: 4px 10px; }
    .tag-diff { color: #c62828; font-weight: bold; }
    .tag-aonly { color: #e65100; }
    .tag-bonly { color: #1565c0; }
    .summary-box { background: #fff; border: 2px solid #1a73e8; border-radius: 6px; padding: 20px; margin-top: 30px; }
    .summary-box h3 { color: #1a73e8; margin-top: 0; }
    .summary-box li { margin: 6px 0; line-height: 1.5; }
    .mac-tag { background: #1a73e8; color: #fff; padding: 2px 8px; border-radius: 3px; font-family: monospace; font-size: 0.85em; }
    .ie-header { background: #e3f2fd; }
    .sub-field { padding-left: 28px !important; font-family: monospace; font-size: 0.82em; }
    .td-field { font-family: monospace; font-size: 0.82em; }
    .td-diff { color: #c62828; font-weight: bold; }
    .td-impact { font-size: 0.78em; color: #555; max-width: 200px; }
    .impact { font-weight: bold; }
    .note { color: #666; font-size: 0.85em; margin-top: 4px; }
    .impact-high { color: #c62828; }
    .impact-mid { color: #e65100; }
    .impact-low { color: #2e7d32; }
    </style>
    """

    # ===== HTML 构建 =====
    html = [f"""<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>802.11 关联协商对比 — {label_a} vs {label_b}</title>{css}</head>
<body>
<h1>📡 802.11 关联协商报文对比分析 <span class="note">(tshark 全字段解析)</span></h1>

<table class="meta">
<tr><td><b>生成时间</b></td><td>{now}</td></tr>
<tr><td><b>文件A</b></td><td><code>{label_a}</code></td></tr>
<tr><td><b>文件B</b></td><td><code>{label_b}</code></td></tr>"""]

    if filter_mac:
        html.append(f'<tr><td><b>过滤MAC</b></td><td><span class="mac-tag">{filter_mac}</span></td></tr>')

    html.append("</table>")

    # ===== 帧数量统计 =====
    html.append("<h2>📊 帧数量统计</h2>")
    html.append("<table><tr><th>帧类型</th><th>文件A</th><th>文件B</th><th>配对</th><th>仅A</th><th>仅B</th></tr>")
    total_a = total_b = total_m = total_oa = total_ob = 0
    all_types = sorted(set(list(frame_stats.keys()) + list(frame_uniq_diffs.keys())), key=frame_sort_key)
    for ft in all_types:
        s = frame_stats.get(ft)
        if s:
            ca = s["match"] + s["only_a"]
            cb = s["match"] + s["only_b"]
            html.append(f"<tr><td>{ft}</td><td>{ca}</td><td>{cb}</td><td>{s['match']}</td><td>{s['only_a']}</td><td>{s['only_b']}</td></tr>")
            total_a += ca; total_b += cb; total_m += s["match"]; total_oa += s["only_a"]; total_ob += s["only_b"]
    html.append(f"<tr style='font-weight:bold'><td>合计</td><td>{total_a}</td><td>{total_b}</td><td>{total_m}</td><td>{total_oa}</td><td>{total_ob}</td></tr>")
    html.append("</table>")

    # ===== 逐帧类型差异 =====
    has_any = False
    all_impacts = []  # 全局收集影响评估
    for ft in all_types:
        uniq = frame_uniq_diffs.get(ft, {})
        extra_a = frame_stats.get(ft, {}).get("only_a", 0)
        extra_b = frame_stats.get(ft, {}).get("only_b", 0)
        if not uniq and extra_a == 0 and extra_b == 0:
            continue
        has_any = True
        html.append(f"<h2>{ft} 差异</h2>")
        if extra_a: html.append(f'<p>⚠ {extra_a} 个{ft}仅存在于 A</p>')
        if extra_b: html.append(f'<p>⚠ {extra_b} 个{ft}仅存在于 B</p>')

        if uniq:
            html.append("<table><tr><th>IE / 子字段</th><th>文件A</th><th>文件B</th><th>差异</th><th>影响评估</th></tr>")
            for ie_id, d in sorted(uniq.items()):
                df = d.get("diffs", {})
                subfields = d.get("subfield_diffs", [])
                name = d["name"]

                if subfields:
                    # 父IE行
                    tags = []
                    if df.get("different"): tags.append('<span class="tag-diff">✗ 值不同</span>')
                    if df.get("missing_in_a"): tags.append('<span class="tag-bonly">⚠ 仅B</span>')
                    if df.get("missing_in_b"): tags.append('<span class="tag-aonly">⚠ 仅A</span>')
                    html.append(
                        f'<tr class="ie-header"><td colspan="5"><b>▸ '
                        + (f"IE-{ie_id} {name}" if ie_id >= 0 else f"📋 {name}")
                        + f'</b> &nbsp;{" ".join(tags)}</td></tr>'
                    )
                    # 每个子字段一行
                    for sf in subfields:
                        va = sf["value_a"][:60]
                        vb = sf["value_b"][:60]
                        same = va == vb
                        # 匹配知识库
                        purpose, effect, impact = get_field_impact(name, sf["field"], va, vb)
                        impact_cell = f'<span class="impact">{impact}</span><br><small>{purpose}</small>' if impact else ""
                        if impact:
                            all_impacts.append((sf["field"], impact, purpose, effect))
                        html.append(
                            f'<tr>'
                            f'<td class="sub-field"><code>{sf["field"]}</code></td>'
                            f'<td class="td-field"><code>{va}</code></td>'
                            f'<td class="td-field"><code>{vb}</code></td>'
                            f'<td class="td-diff">{"=" if same else "≠"}</td>'
                            f'<td class="td-impact">{impact_cell}</td>'
                            f'</tr>'
                        )
                else:
                    # 无子字段差异的 IE (不太会出现，因为 tshark 总会有子字段)
                    tags = []
                    if df.get("different"): tags.append('<span class="tag-diff">✗ 值不同</span>')
                    if df.get("missing_in_a"): tags.append('<span class="tag-bonly">⚠ 仅B</span>')
                    if df.get("missing_in_b"): tags.append('<span class="tag-aonly">⚠ 仅A</span>')
                    html.append(
                        f"<tr><td><b>{'IE-'+str(ie_id) if ie_id>=0 else '📋'} {name}</b></td>"
                        f"<td>—</td><td>—</td><td>{' '.join(tags)}</td></tr>"
                    )
            html.append("</table>")

    if not has_any:
        html.append('<p>✅ 两份抓包管理帧完全一致</p>')

    # ===== 差异化分析 =====
    html.append('<div class="summary-box"><h3>📝 差异化分析</h3>')

    analysis = []

    # 提取 SSID、信道、HT 能力等关键差异
    ssid_a = ssid_b = None
    ht_40_a = ht_40_b = None
    ht_ss_a = ht_ss_b = None
    sgi_a = sgi_b = None
    vht_a = vht_b = False
    he_a = he_b = False

    for ft in all_types:
        uniq = frame_uniq_diffs.get(ft, {})
        for ie_id, d in uniq.items():
            df = d.get("diffs", {})
            # SSID
            if ie_id == 0 and df.get("different"):
                for sf in d.get("subfield_diffs", []):
                    if sf["field"] == "SSID":
                        ssid_a = sf["value_a"].strip('"')
                        ssid_b = sf["value_b"].strip('"')
            # HT: 40MHz support
            if ie_id == 45:
                for sf in d.get("subfield_diffs", []):
                    if "40MHz" in sf["field"]:
                        ht_40_a = sf["value_a"]
                        ht_40_b = sf["value_b"]
                    if "Max SS" in sf["field"] or "Spatial Stream" in sf["field"] or "MCS Set" in sf["field"]:
                        # Try to extract spatial stream count from MCS info
                        pass
            # Short GI
            if ie_id == 45:
                for sf in d.get("subfield_diffs", []):
                    if "Short GI" in sf["field"]:
                        if sgi_a is None:
                            sgi_a = sf["value_a"]
                            sgi_b = sf["value_b"]
            # VHT
            if ie_id == 191:
                if df.get("missing_in_b"): vht_a = True
                if df.get("missing_in_a") or df.get("different"): vht_b = True
            # HE
            if ie_id in (255,):
                if df.get("missing_in_b") or df.get("different"): he_a = True
                if df.get("missing_in_a") or df.get("different"): he_b = True

    if ssid_a and ssid_b and ssid_a != ssid_b:
        analysis.append(f'目标SSID不同: A="{ssid_a}" vs B="{ssid_b}"')

    gen_a = "802.11ax(HE)" if he_a else ("802.11ac(VHT)" if vht_a else "802.11n(HT)")
    gen_b = "802.11ax(HE)" if he_b else ("802.11ac(VHT)" if vht_b else "802.11n(HT)")
    if gen_a != gen_b:
        analysis.append(f'Wi-Fi代际: A={gen_a}, B={gen_b}')

    if ht_40_a and ht_40_b and ht_40_a != ht_40_b:
        analysis.append(f'40MHz信道支持: A={ht_40_a}, B={ht_40_b}')

    if sgi_a and sgi_b and sgi_a != sgi_b:
        analysis.append(f'Short-GI: A={sgi_a}, B={sgi_b}')

    # 帧数量差异
    for ft in all_types:
        s = frame_stats.get(ft, {})
        if s.get("only_a", 0) > 5:
            analysis.append(f'{ft}: A多{s["only_a"]}个 — A的抓包覆盖范围更大')
        if s.get("only_b", 0) > 5:
            analysis.append(f'{ft}: B多{s["only_b"]}个 — B的抓包覆盖范围更大')

    if analysis:
        html.append("<ol>")
        for a in analysis[:12]:
            html.append(f"<li>{a}</li>")
        html.append("</ol>")
    else:
        html.append("<p>✅ 未发现明显差异</p>")

    html.append(f"<p><b>统计:</b> {ie_diff_count} 个IE字段有差异 (含 {sub_diff_count} 个子字段差异)</p>")
    html.append("</div>")

    # ===== 综合影响分析 =====
    if all_impacts:
        # 按影响等级分组
        high = [(f, i, p, e) for f, i, p, e in all_impacts if "🔴" in i]
        mid = [(f, i, p, e) for f, i, p, e in all_impacts if "🟡" in i]
        low = [(f, i, p, e) for f, i, p, e in all_impacts if "🟢" in i]

        html.append('<div class="summary-box"><h3>📊 综合影响分析</h3>')

        if high:
            html.append('<p class="impact-high"><b>🔴 高影响差异 ({0} 项) — 对吞吐量/安全性/关联有显著影响</b></p>'.format(len(high)))
            html.append('<ul>')
            for field, impact, purpose, effect in high[:10]:
                html.append(f'<li><b>{field}</b> — {purpose}：{effect} <span class="impact-high">[{impact}]</span></li>')
            html.append('</ul>')

        if mid:
            html.append('<p class="impact-mid"><b>🟡 中等影响差异 ({0} 项) — 影响QoS/覆盖/漫游等功能</b></p>'.format(len(mid)))
            html.append('<ul>')
            for field, impact, purpose, effect in mid[:10]:
                html.append(f'<li><b>{field}</b> — {purpose}：{effect} <span class="impact-mid">[{impact}]</span></li>')
            html.append('</ul>')

        if low:
            html.append(f'<p class="impact-low"><b>🟢 低影响差异 ({len(low)} 项) — 微调参数或兼容性标志</b></p>')

        html.append('</div>')

    html.append("<p class='note'>⚡ 基于 tshark (Wireshark) 完整 802.11 协议栈解析，覆盖全部 IE ID 及子字段</p>")
    html.append("</body></html>")

    report = "\n".join(html)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report saved: {output_path}")
    return report


# ===========================================================================
# 大文件预处理 (tshark 管理帧预过滤)
# ===========================================================================

TSHARK_LARGE_THRESHOLD = 100 * 1024 * 1024  # 100MB


def prefilter_mgmt(input_path, label):
    """用 tshark 过滤管理帧到临时文件。"""
    size_mb = os.path.getsize(input_path) / (1024 * 1024)
    print(f"  {label}: {size_mb:.0f}MB, pre-filtering management frames...")

    tmp = tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False)
    tmp.close()

    try:
        subprocess.run(
            ["tshark", "-r", input_path, "-Y", "wlan.fc.type == 0", "-w", tmp.name],
            check=True, capture_output=True, timeout=300
        )
    except subprocess.CalledProcessError as e:
        print(f"  tshark error: {e.stderr.decode()[:200]}")
        os.unlink(tmp.name)
        return None
    except FileNotFoundError:
        print("  tshark not found! Install: sudo apt install tshark")
        os.unlink(tmp.name)
        return None

    count = 0
    try:
        r = subprocess.run(["tshark", "-r", tmp.name], capture_output=True, timeout=30)
        count = len([l for l in r.stderr.decode().splitlines() if l.strip()])
    except Exception:
        pass

    print(f"  → {count} management frames extracted to temp file")
    return tmp.name


# ===========================================================================
# 主函数
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="802.11 关联协商报文对比分析 (tshark 全字段解析版)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 assoc_diff.py sta_good.pcap sta_bad.pcap
  python3 assoc_diff.py ap1.pcap ap2.pcap -o report.html
  python3 assoc_diff.py large_a.pcapng large_b.pcapng -m ac:22:0b:93:5d:8d
        """
    )
    parser.add_argument("file_a", help="第一个抓包文件 (pcap/pcapng)")
    parser.add_argument("file_b", help="第二个抓包文件 (pcap/pcapng)")
    parser.add_argument("-o", "--output", help="输出报告文件路径 (默认: stdout)")
    parser.add_argument("--filter-mac", "-m", default="",
                        help="仅分析指定MAC地址相关的管理帧")
    parser.add_argument("--no-prefilter", action="store_true",
                        help="禁用 tshark 自动预过滤")
    parser.add_argument("--keep-temp", action="store_true",
                        help="保留预过滤临时文件")

    args = parser.parse_args()

    for f in [args.file_a, args.file_b]:
        if not os.path.exists(f):
            print(f"Error: 文件不存在: {f}")
            sys.exit(1)

    label_a = os.path.basename(args.file_a)
    label_b = os.path.basename(args.file_b)

    # ==== 大文件自动预过滤 ====
    temp_files = []
    file_a_load = args.file_a
    file_b_load = args.file_b

    for src, lbl in [(args.file_a, label_a), (args.file_b, label_b)]:
        size = os.path.getsize(src)
        if not args.no_prefilter and size > TSHARK_LARGE_THRESHOLD:
            tmp = prefilter_mgmt(src, lbl)
            if tmp:
                temp_files.append(tmp)
                if src == args.file_a:
                    file_a_load = tmp
                else:
                    file_b_load = tmp

    # ==== tshark 解析管理帧 ====
    print(f"\nParsing management frames from {os.path.basename(file_a_load)}...")
    text_a = run_tshark_verbose(file_a_load, args.filter_mac)
    if text_a is None:
        print("Failed to run tshark on file A")
        sys.exit(1)
    frames_a = parse_tshark_verbose(text_a)
    print(f"  {len(frames_a)} management frames (MAC filtered)")

    print(f"Parsing management frames from {os.path.basename(file_b_load)}...")
    text_b = run_tshark_verbose(file_b_load, args.filter_mac)
    if text_b is None:
        print("Failed to run tshark on file B")
        sys.exit(1)
    frames_b = parse_tshark_verbose(text_b)
    print(f"  {len(frames_b)} management frames (MAC filtered)")

    # ==== 分组 ====
    grouped_a = group_frames_tshark(frames_a)
    grouped_b = group_frames_tshark(frames_b)

    print(f"\nFrame types in A: {list(grouped_a.keys())}")
    print(f"Frame types in B: {list(grouped_b.keys())}")
    if args.filter_mac:
        print(f"  (filtered by MAC: {args.filter_mac})")

    # ==== 匹配 ====
    pairs = match_frames(grouped_a, grouped_b)
    print(f"Matched pairs: {len(pairs)}")

    # ==== 生成报告 ====
    report = generate_report(pairs, label_a, label_b, args.filter_mac, args.output)
    print(report)

    # ==== 清理 ====
    if not args.keep_temp:
        for f in temp_files:
            try:
                os.unlink(f)
            except Exception:
                pass


if __name__ == "__main__":
    main()
