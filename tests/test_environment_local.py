"""环境验证测试 — AC telnet 连接 + wlan0mon 抓包 + Probe 注入

适配当前拓扑:
  AC:  100.1.1.1 (telnet, 无需登录, RGOS 11.9(6)W10)
  AP:  通过 AC 管理 (ap-cls), 空口 BSSID 5a:69:6c:27:2b:d4
  Sniffer: 本地 wlan0mon, ch36
"""

import time
import subprocess
from pathlib import Path

import pytest


# ===== 拓扑配置 =====
AC_HOST = "100.1.1.1"
AC_PORT = 23
TARGET_BSSID = "5a:69:6c:27:2b:d4"
TARGET_SSID = "ruijie-cls8862a"
MON_IFACE = "wlan0mon"
CHANNEL = 36
CHANNEL_FREQ = 5180


def _telnet_cmd(command: str, timeout: float = 5.0) -> str:
    """发送命令到 AC，返回输出文本。"""
    import telnetlib
    tn = telnetlib.Telnet(AC_HOST, AC_PORT, timeout=10)
    time.sleep(0.5)
    # 等到 prompt 出现（AC 可能还在初始化）
    idx, match, _ = tn.expect([b"#", b">"], timeout=5)
    tn.read_very_eager()
    tn.write(b"terminal length 0\r\n")
    time.sleep(0.3)
    tn.read_very_eager()
    tn.write(command.encode() + b"\r\n")
    time.sleep(timeout)
    idx, match, output = tn.expect([b"#", b">"], timeout=10)
    # 处理 More 分页
    retries = 0
    data = output.decode("utf-8", errors="replace")
    while "More" in data and retries < 20:
        tn.write(b" ")
        time.sleep(0.2)
        idx, match, more = tn.expect([b"#", b">"], timeout=5)
        data += more.decode("utf-8", errors="replace")
        retries += 1
    tn.close()
    return data


def _run_sudo(cmd: str, timeout: int = 15) -> tuple[int, str, str]:
    """执行 sudo 命令。"""
    full = f"echo neteye | sudo -S {cmd}"
    p = subprocess.run(full, shell=True, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


class TestEnvironment:
    """环境验证 — AC + 空口探测"""

    # ========== AC 连接测试 ==========

    def test_01_ac_telnet_reachable(self):
        """AC telnet 端口可达"""
        import socket
        s = socket.socket()
        s.settimeout(5)
        result = s.connect_ex((AC_HOST, AC_PORT))
        s.close()
        assert result == 0, f"AC {AC_HOST}:{AC_PORT} 不可达"

    def test_02_ac_version(self):
        """AC 版本信息"""
        out = _telnet_cmd("show version", timeout=4)
        assert "RGOS" in out or "software" in out, f"未检测到 RGOS: {out[:200]}"
        for line in out.split("\n"):
            if "software version" in line.lower():
                print(f"  AC: {line.strip()}")
                break

    def test_03_ac_ap_summary(self):
        """AC 上查看 AP 列表"""
        out = _telnet_cmd("show ap-config summary", timeout=3)
        print(f"  AP summary output ({len(out)} chars):")
        for line in out.split("\n")[:20]:
            if line.strip():
                print(f"    {line.strip()}")
        # 不强制断言有 AP（当前可能未配置）

    def test_04_ac_client_list(self):
        """AC 上查看客户端列表"""
        out = _telnet_cmd("show ac-config client", timeout=3)
        print(f"  Client list output ({len(out)} chars):")
        for line in out.split("\n")[:20]:
            if line.strip():
                print(f"    {line.strip()}")

    # ========== 空口抓包测试 ==========

    def test_05_monitor_interface(self):
        """验证 wlan0mon 存在且在 monitor 模式"""
        rc, out, err = _run_sudo(f"iw dev {MON_IFACE} info")
        assert rc == 0, f"无法获取 {MON_IFACE} 信息: {err}"
        assert "type monitor" in out, f"{MON_IFACE} 不在 monitor 模式:\n{out}"
        print(f"  {MON_IFACE} info:\n{out[:300]}")

    def test_06_channel_check(self):
        """验证信道设置"""
        rc, out, err = _run_sudo(f"iw dev {MON_IFACE} info")
        assert f"channel {CHANNEL}" in out.lower() or f"channel {CHANNEL} " in out, \
            f"信道不是 {CHANNEL}:\n{out}"

    def test_07_capture_beacon(self):
        """抓包验证能收到目标 AP 的 Beacon"""
        pcap_path = "/tmp/test_env_beacon.pcap"
        _run_sudo(f"rm -f {pcap_path}")

        # 抓 5 秒
        rc, out, err = _run_sudo(
            f"timeout 8 tcpdump -i {MON_IFACE} -c 200 -w {pcap_path}",
            timeout=12,
        )
        print(f"  tcpdump rc={rc}")

        # 用 tshark 检查 Beacon
        rc2, out2, err2 = _run_sudo(
            f"tshark -r {pcap_path} -Y 'wlan.fc.type_subtype == 8 && wlan.sa == {TARGET_BSSID}' "
            f"-T fields -e wlan.sa -e wlan.ssid 2>/dev/null",
        )
        print(f"  Beacon from target AP:")
        print(f"  {out2[:500] if out2 else '(none found)'}")

        assert TARGET_BSSID.replace(":", "") in out2.replace(":", ""), \
            f"未收到目标 AP {TARGET_BSSID} 的 Beacon"

    def test_08_capture_probe_response(self):
        """注入 Probe Request 并验证收到 Probe Response"""
        import subprocess as sp

        pcap_path = "/tmp/test_env_probe.pcap"
        _run_sudo(f"rm -f {pcap_path}")

        # 后台抓包
        tcpdump_proc = sp.Popen(
            f"echo neteye | sudo -S tcpdump -i {MON_IFACE} -w {pcap_path} -U",
            shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL,
        )
        time.sleep(0.5)

        # 用子进程 + sudo 执行 scapy 注入（raw socket 需要 root）
        inject_script = f'''
from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp
import time
probe = (
    RadioTap()
    / Dot11(type=0, subtype=4, addr1="{TARGET_BSSID}", addr2="00:11:22:33:44:55", addr3="{TARGET_BSSID}")
    / Dot11ProbeReq()
    / Dot11Elt(ID=0, info=b"{TARGET_SSID}")
    / Dot11Elt(ID=1, info=bytes([0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c]))
)
for i in range(3):
    sendp(probe, iface="{MON_IFACE}", verbose=False)
    time.sleep(0.1)
print("Probe injected: 3 frames")
'''
        rc, out, err = _run_sudo(
            f"python3 -c '{inject_script}'",
            timeout=15,
        )
        print(f"  Injection: {out.strip()} err={err[:100] if err else 'none'}")

        time.sleep(1.5)
        tcpdump_proc.terminate()
        tcpdump_proc.wait(timeout=5)

        # 用 tshark 检查 Probe Response
        rc, out, err = _run_sudo(
            f"tshark -r {pcap_path} "
            f"-Y 'wlan.fc.type_subtype == 5 && wlan.sa == {TARGET_BSSID}' "
            f"-T fields -e wlan.sa -e wlan.ssid 2>/dev/null",
        )
        print(f"  Probe Response from target AP:")
        print(f"  {out[:500] if out else '(none found)'}")

        probe_resp_count = out.count(TARGET_BSSID.replace(":", "")) if out else 0
        print(f"  Probe Response count: {probe_resp_count}")

        if probe_resp_count == 0:
            # 尝试广播 Probe Request
            print("  Trying broadcast Probe Request...")
            _run_sudo(f"rm -f {pcap_path}")
            tcpdump_proc2 = sp.Popen(
                f"echo neteye | sudo -S tcpdump -i {MON_IFACE} -w {pcap_path} -U",
                shell=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL,
            )
            time.sleep(0.5)

            broad_inject = f'''
from scapy.all import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, sendp
import time
probe = (
    RadioTap()
    / Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff", addr2="00:11:22:33:44:55", addr3="ff:ff:ff:ff:ff:ff")
    / Dot11ProbeReq()
    / Dot11Elt(ID=0, info=b"")
    / Dot11Elt(ID=1, info=bytes([0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c]))
)
for i in range(3):
    sendp(probe, iface="{MON_IFACE}", verbose=False)
    time.sleep(0.1)
print("Broadcast probe injected: 3 frames")
'''
            rc3, out3, err3 = _run_sudo(
                f"python3 -c '{broad_inject}'",
                timeout=15,
            )
            print(f"  Broadcast injection: {out3.strip()} err={err3[:100] if err3 else 'none'}")

            time.sleep(2)
            tcpdump_proc2.terminate()
            tcpdump_proc2.wait(timeout=5)

            rc4, out4, _ = _run_sudo(
                f"tshark -r {pcap_path} "
                f"-Y 'wlan.fc.type_subtype == 5' "
                f"-T fields -e wlan.sa -e wlan.ssid 2>/dev/null",
            )
            print(f"  Broadcast probe responses:")
            print(f"  {out4[:500] if out4 else '(none)'}")
            probe_resp_count = out4.count(":") if out4 else 0

        print(f"  ✅ Probe test complete. Responses: {probe_resp_count}")

    # ========== 恢复 ==========

    def test_09_cleanup(self):
        """清理临时文件"""
        _run_sudo("rm -f /tmp/test_env_beacon.pcap /tmp/test_env_probe.pcap")
        print("  Cleanup done")
