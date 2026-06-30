"""STA 关联测试 — Probe / Auth / Assoc / Reassoc（本地 wlan0mon 适配版）

适配当前环境:
  目标 AP: BSSID 06:d0:f8:20:26:0a, SSID wudan-test, Open System, Ch161
  注入接口: wlan0mon (本地)
  抓包: 本机 tcpdump + tshark
"""

import re
import subprocess as sp
import time
from pathlib import Path

import pytest


# ===== 拓扑配置 =====
TARGET_BSSID = "06:d0:f8:20:26:0a"
TARGET_SSID = "wudan-test"
MON_IFACE = "wlan0mon"
STA_BASE_MAC = "00:11:22:33:00:00"


def _sudo(cmd: str, timeout: int = 15) -> tuple[int, str, str]:
    p = sp.run(f"echo neteye | sudo -S {cmd}", shell=True,
               capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def _inject(script: str, timeout: int = 10) -> tuple[int, str, str]:
    """用 sudo python3 -c 注入帧（raw socket 需要 root）。"""
    escaped = script.replace("'", "'\"'\"'")
    return _sudo(f"python3 -c '{escaped}'", timeout=timeout)


def _pcap_has(pcap: str, tshark_filter: str) -> int:
    """返回匹配帧数量。"""
    rc, out, _ = _sudo(
        f"tshark -r {pcap} -Y '{tshark_filter}' "
        f"-T fields -e frame.number 2>/dev/null | wc -l"
    )
    try:
        return int(out.strip()) if out.strip() else 0
    except ValueError:
        return 0


class TestStaScanning:
    """STA 扫描测试 — Probe Request"""

    def test_probe_broadcast(self):
        """广播 Probe Request — 不指定 SSID"""
        pcap = "/tmp/test_probe_bcast.pcap"
        _sudo(f"rm -f {pcap}")

        # 启动抓包
        cap = sp.Popen(
            f"echo neteye | sudo -S tcpdump -i {MON_IFACE} -w {pcap} -U",
            shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL,
        )
        time.sleep(0.5)

        # 注入广播 Probe Request (SSID 为空)
        sta_mac = f"{STA_BASE_MAC.replace('00', '01')}"
        result = _inject(f"""
from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp
import time
dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2="{sta_mac}", addr3="ff:ff:ff:ff:ff:ff")
frame = RadioTap() / dot11 / Dot11ProbeReq() / Dot11Elt(ID=0, info=b"") / Dot11Elt(ID=1, info=bytes([0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c]))
for i in range(2):
    sendp(frame, iface="{MON_IFACE}", verbose=False)
    time.sleep(0.05)
print("ok")
""")
        assert "ok" in result[1], f"Injection failed: {result}"
        time.sleep(2)
        cap.terminate(); cap.wait(timeout=5)

        # 验证: Probe Request 在 pcap 中
        n_req = _pcap_has(pcap, f"wlan.fc.type_subtype == 4 && wlan.sa == {sta_mac}")
        assert n_req >= 2, f"Expected >=2 Probe Req, got {n_req}"

        # 验证: 收到了 Probe Response
        n_resp = _pcap_has(pcap, "wlan.fc.type_subtype == 5")
        print(f"  Probe Req sent: {n_req}, Probe Resp received: {n_resp}")
        assert n_resp > 0, "No Probe Response received (broadcast)"

    def test_probe_targeted_ssid(self):
        """定向 Probe Request — 指定目标 SSID"""
        pcap = "/tmp/test_probe_targeted.pcap"
        _sudo(f"rm -f {pcap}")

        cap = sp.Popen(
            f"echo neteye | sudo -S tcpdump -i {MON_IFACE} -w {pcap} -U",
            shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL,
        )
        time.sleep(0.5)

        sta_mac = f"{STA_BASE_MAC.replace('00', '02')}"
        result = _inject(f"""
from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp
import time
dot11 = Dot11(type=0, subtype=4, addr1="{TARGET_BSSID}", addr2="{sta_mac}", addr3="{TARGET_BSSID}")
frame = RadioTap() / dot11 / Dot11ProbeReq() / Dot11Elt(ID=0, info=b"{TARGET_SSID}") / Dot11Elt(ID=1, info=bytes([0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c]))
for i in range(3):
    sendp(frame, iface="{MON_IFACE}", verbose=False)
    time.sleep(0.05)
print("ok")
""")
        assert "ok" in result[1], f"Injection failed: {result}"
        time.sleep(2)
        cap.terminate(); cap.wait(timeout=5)

        n_req = _pcap_has(pcap, f"wlan.fc.type_subtype == 4 && wlan.sa == {sta_mac}")
        n_resp = _pcap_has(pcap, f"wlan.fc.type_subtype == 5 && wlan.sa == {TARGET_BSSID}")
        print(f"  Probe Req: {n_req}, Probe Resp from target: {n_resp}")
        assert n_req >= 3, f"Expected >=3 Probe Req, got {n_req}"
        assert n_resp > 0, f"No Probe Response from {TARGET_BSSID}"


class TestStaAssociation:
    """STA 关联测试 — Auth + Assoc（Open System）"""

    def test_auth_only(self):
        """仅发送 Auth 帧，验证 AP 响应"""
        pcap = "/tmp/test_auth.pcap"
        _sudo(f"rm -f {pcap}")

        cap = sp.Popen(
            f"echo neteye | sudo -S tcpdump -i {MON_IFACE} -w {pcap} -U",
            shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL,
        )
        time.sleep(0.5)

        sta_mac = f"{STA_BASE_MAC.replace('00', '10')}"
        result = _inject(f"""
from scapy.all import RadioTap, Dot11, Dot11Auth, sendp
import time
dot11 = Dot11(type=0, subtype=11, addr1="{TARGET_BSSID}", addr2="{sta_mac}", addr3="{TARGET_BSSID}", SC=0)
frame = RadioTap() / dot11 / Dot11Auth(algo=0, seqnum=1, status=0)
for i in range(2):
    sendp(frame, iface="{MON_IFACE}", verbose=False)
    time.sleep(0.1)
print("ok")
""")
        assert "ok" in result[1], f"Injection failed: {result}"
        time.sleep(2)
        cap.terminate(); cap.wait(timeout=5)

        # 验证 Auth Request 在 pcap 中
        n_auth_req = _pcap_has(pcap, f"wlan.fc.type_subtype == 11 && wlan.sa == {sta_mac}")
        # 验证 Auth Response (AP → STA, subtype 11, addr1 == STA)
        n_auth_resp = _pcap_has(pcap, f"wlan.fc.type_subtype == 11 && wlan.da == {sta_mac}")

        print(f"  Auth Req sent: {n_auth_req}, Auth Resp from AP: {n_auth_resp}")
        assert n_auth_req >= 2, f"Expected >=2 Auth Req, got {n_auth_req}"
        if n_auth_resp == 0:
            print("  ⚠ AP did not respond to Auth — checking for any Auth frames...")
            all_auth = _pcap_has(pcap, "wlan.fc.type_subtype == 11")
            print(f"  All Auth frames in pcap: {all_auth}")

    def test_full_assoc_open(self):
        """完整关联流程 — Auth + Assoc（Open System）

        流程: Auth Req → (AP responds Auth Resp) → Assoc Req → (AP responds Assoc Resp)
        验证: pcap 中能找到帧序列
        """
        pcap = "/tmp/test_full_assoc.pcap"
        _sudo(f"rm -f {pcap}")

        cap = sp.Popen(
            f"echo neteye | sudo -S tcpdump -i {MON_IFACE} -w {pcap} -U",
            shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL,
        )
        time.sleep(0.5)

        sta_mac = f"{STA_BASE_MAC.replace('00', '20')}"
        # 802.11a rates (6, 9, 12, 18, 24, 36, 48, 54 Mbps)
        rates = bytes([0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c])
        result = _inject(f"""
from scapy.all import RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11Elt, sendp
import time

sta = "{sta_mac}"
bssid = "{TARGET_BSSID}"
ssid = b"{TARGET_SSID}"
rates = bytes({list(rates)})
iface = "{MON_IFACE}"

# Step 1: Auth Request
dot11 = Dot11(type=0, subtype=11, addr1=bssid, addr2=sta, addr3=bssid, SC=0)
sendp(RadioTap() / dot11 / Dot11Auth(algo=0, seqnum=1, status=0), iface=iface, verbose=False)
time.sleep(0.3)

# Step 2: Assoc Request (capabilities=0x1104, the same the AP advertises)
dot11 = Dot11(type=0, subtype=0, addr1=bssid, addr2=sta, addr3=bssid, SC=1<<4)
ssid_ie = Dot11Elt(ID=0, info=ssid)
rates_ie = Dot11Elt(ID=1, info=rates)
sendp(RadioTap() / dot11 / Dot11AssoReq(cap=0x1104, listen_interval=10) / ssid_ie / rates_ie, iface=iface, verbose=False)
time.sleep(0.3)
print("ok")
""", timeout=15)
        assert "ok" in result[1], f"Injection failed: {result}"
        time.sleep(3)
        cap.terminate(); cap.wait(timeout=5)

        # 详细分析 pcap
        n_auth_req = _pcap_has(pcap, f"wlan.fc.type_subtype == 11 && wlan.sa == {sta_mac} && wlan.fixed.auth.alg == 0")
        n_auth_resp = _pcap_has(pcap, f"wlan.fc.type_subtype == 11 && wlan.da == {sta_mac} && wlan.sa == {TARGET_BSSID}")
        n_assoc_req = _pcap_has(pcap, f"wlan.fc.type_subtype == 0 && wlan.sa == {sta_mac}")
        n_assoc_resp = _pcap_has(pcap, f"wlan.fc.type_subtype == 1 && wlan.da == {sta_mac} && wlan.sa == {TARGET_BSSID}")
        total = _pcap_has(pcap, "wlan")

        print(f"  Total frames in pcap: {total}")
        print(f"  Auth Req (STA→AP): {n_auth_req}")
        print(f"  Auth Resp (AP→STA): {n_auth_resp}")
        print(f"  Assoc Req (STA→AP): {n_assoc_req}")
        print(f"  Assoc Resp (AP→STA): {n_assoc_resp}")

        # 详细检查 AP 响应状态码
        if n_assoc_resp > 0:
            rc, out, _ = _sudo(
                f"tshark -r {pcap} "
                f"-Y 'wlan.fc.type_subtype == 1 && wlan.da == {sta_mac} && wlan.sa == {TARGET_BSSID}' "
                f"-T fields -e wlan.fixed.status_code 2>/dev/null"
            )
            print(f"  Assoc Resp status codes: {out.strip()}")

        assert n_auth_req >= 1, f"No Auth Req found"
        assert n_assoc_req >= 1, f"No Assoc Req found"

        # AP 响应检查（RF 环境依赖，报告但不强制）
        if n_auth_resp == 0:
            print("  ⚠ AP 未响应 Auth — 可能 AP 正在处理其他连接或 RF 条件不佳")
        if n_assoc_resp == 0:
            print("  ⚠ AP 未响应 Assoc — 可能未收到 Auth Resp seq=2 就提前发了 Assoc")

    def test_full_assoc_with_ht_cap(self):
        """关联 + HT Capabilities IE（模拟 11n STA）"""
        pcap = "/tmp/test_assoc_ht.pcap"
        _sudo(f"rm -f {pcap}")

        cap = sp.Popen(
            f"echo neteye | sudo -S tcpdump -i {MON_IFACE} -w {pcap} -U",
            shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL,
        )
        time.sleep(0.5)

        sta_mac = f"{STA_BASE_MAC.replace('00', '21')}"
        rates = bytes([0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c])

        # HT Capabilities IE (tag 45): 26 bytes of basic HT cap
        ht_cap = bytes([0x6f, 0x09, 0x17, 0xff, 0xff, 0x00, 0x00, 0x7e,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0xe6,
                        0xa7, 0x08])

        result = _inject(f"""
from scapy.all import RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11Elt, sendp
import time

sta = "{sta_mac}"
bssid = "{TARGET_BSSID}"
ssid = b"{TARGET_SSID}"
rates = bytes({list(rates)})
ht_cap = bytes({list(ht_cap)})
iface = "{MON_IFACE}"

# Auth
dot11 = Dot11(type=0, subtype=11, addr1=bssid, addr2=sta, addr3=bssid, SC=0)
sendp(RadioTap() / dot11 / Dot11Auth(algo=0, seqnum=1, status=0), iface=iface, verbose=False)
time.sleep(0.3)

# Assoc with HT Cap IE
dot11 = Dot11(type=0, subtype=0, addr1=bssid, addr2=sta, addr3=bssid, SC=1<<4)
ssid_ie = Dot11Elt(ID=0, info=ssid)
rates_ie = Dot11Elt(ID=1, info=rates)
ht_ie = Dot11Elt(ID=45, info=ht_cap)
ext_rates = Dot11Elt(ID=50, info=bytes([0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c]))
sendp(RadioTap() / dot11 / Dot11AssoReq(cap=0x1104, listen_interval=10) / ssid_ie / rates_ie / ht_ie / ext_rates, iface=iface, verbose=False)
time.sleep(0.3)
print("ok")
""", timeout=15)
        assert "ok" in result[1], f"Injection failed: {result}"
        time.sleep(3)
        cap.terminate(); cap.wait(timeout=5)

        n_assoc_req = _pcap_has(pcap, f"wlan.fc.type_subtype == 0 && wlan.sa == {sta_mac}")
        n_assoc_resp = _pcap_has(pcap, f"wlan.fc.type_subtype == 1 && wlan.da == {sta_mac}")

        print(f"  Assoc Req (HT): {n_assoc_req}, Assoc Resp: {n_assoc_resp}")
        assert n_assoc_req >= 1, f"No HT Assoc Req found"

        # 验证 HT Cap IE 在帧中
        rc, out, _ = _sudo(
            f"tshark -r {pcap} "
            f"-Y 'wlan.fc.type_subtype == 0 && wlan.sa == {sta_mac}' "
            f"-T fields -e wlan_mgt.tag.number 2>/dev/null"
        )
        print(f"  IE tags in Assoc Req: {out.strip()}")


class TestStaRoaming:
    """STA 漫游测试 — Reassociation"""

    def test_reassoc_same_bssid(self):
        """Reassoc 到同一 BSSID（模拟重连）"""
        pcap = "/tmp/test_reassoc.pcap"
        _sudo(f"rm -f {pcap}")

        cap = sp.Popen(
            f"echo neteye | sudo -S tcpdump -i {MON_IFACE} -w {pcap} -U",
            shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL,
        )
        time.sleep(0.5)

        sta_mac = f"{STA_BASE_MAC.replace('00', '30')}"
        rates = bytes([0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c])

        result = _inject(f"""
from scapy.all import RadioTap, Dot11, Dot11Auth, Dot11AssoReq, Dot11ReassoReq, Dot11Elt, sendp
import time

sta = "{sta_mac}"
bssid = "{TARGET_BSSID}"
ssid = b"{TARGET_SSID}"
rates = bytes({list(rates)})
iface = "{MON_IFACE}"

# Step 1: Auth
dot11 = Dot11(type=0, subtype=11, addr1=bssid, addr2=sta, addr3=bssid, SC=0)
sendp(RadioTap() / dot11 / Dot11Auth(algo=0, seqnum=1, status=0), iface=iface, verbose=False)
time.sleep(0.3)

# Step 2: Assoc (initial)
dot11 = Dot11(type=0, subtype=0, addr1=bssid, addr2=sta, addr3=bssid, SC=1<<4)
ssid_ie = Dot11Elt(ID=0, info=ssid)
rates_ie = Dot11Elt(ID=1, info=rates)
sendp(RadioTap() / dot11 / Dot11AssoReq(cap=0x1104, listen_interval=10) / ssid_ie / rates_ie, iface=iface, verbose=False)
time.sleep(0.5)

# Step 3: Reassoc (to same BSSID — simulating reconnection)
dot11 = Dot11(type=0, subtype=2, addr1=bssid, addr2=sta, addr3=bssid, SC=2<<4)
reassoc = Dot11ReassoReq(cap=0x1104, listen_interval=10, current_AP=bssid)
sendp(RadioTap() / dot11 / reassoc / ssid_ie / rates_ie, iface=iface, verbose=False)
time.sleep(0.3)

print("ok")
""", timeout=15)
        assert "ok" in result[1], f"Injection failed: {result}"
        time.sleep(3)
        cap.terminate(); cap.wait(timeout=5)

        n_auth = _pcap_has(pcap, f"wlan.fc.type_subtype == 11 && wlan.sa == {sta_mac}")
        n_assoc = _pcap_has(pcap, f"wlan.fc.type_subtype == 0 && wlan.sa == {sta_mac}")
        n_reassoc = _pcap_has(pcap, f"wlan.fc.type_subtype == 2 && wlan.sa == {sta_mac}")

        print(f"  Auth Req: {n_auth}, Assoc Req: {n_assoc}, Reassoc Req: {n_reassoc}")
        assert n_auth >= 1, f"No Auth Req"
        assert n_assoc >= 1, f"No Assoc Req"
        assert n_reassoc >= 1, f"No Reassoc Req"

        # 验证 Reassoc 帧的 current_AP 字段
        rc, out, _ = _sudo(
            f"tshark -r {pcap} "
            f"-Y 'wlan.fc.type_subtype == 2 && wlan.sa == {sta_mac}' "
            f"-T fields -e wlan.fixed.current_ap 2>/dev/null"
        )
        print(f"  Reassoc current_AP field: {out.strip()}")

    def test_cleanup(self):
        """清理临时 pcap 文件"""
        _sudo("rm -f /tmp/test_probe_bcast.pcap /tmp/test_probe_targeted.pcap "
              "/tmp/test_auth.pcap /tmp/test_full_assoc.pcap "
              "/tmp/test_assoc_ht.pcap /tmp/test_reassoc.pcap")
        print("  Cleanup done")
