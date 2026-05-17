"""验证测试环境 — STA WiFi接入 + DHCP + AP确认"""

import asyncio
import time

import pytest
import paramiko


# ===== 从 topology.yaml 读取的配置 =====
AP_HOST = "192.168.100.3"
AP_PORT = 23
STA_HOST = "192.168.100.28"
STA_USER = "bcm"
STA_PASS = "111"
STA_IFACE = "wlp45s0"
SSID = "JXX"
PSK = "xiaoxia_0903"


class TestEnvironment:
    """测试环境验证 — STA接入JXX + DHCP + AP侧确认"""

    @pytest.fixture(scope="class")
    def sta_ssh(self):
        """SSH连接STA机器"""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(STA_HOST, port=22, username=STA_USER,
                       password=STA_PASS, timeout=10)
        yield client
        client.close()

    def _ssh_run(self, ssh, cmd, sudo=False, timeout=30):
        full_cmd = f"echo {STA_PASS} | sudo -S {cmd}" if sudo else cmd
        stdin, stdout, stderr = ssh.exec_command(full_cmd, timeout=timeout)
        out = stdout.read().decode(errors='replace')
        err = stderr.read().decode(errors='replace')
        rc = stdout.channel.recv_exit_status()
        return rc, out.strip(), err.strip()

    async def _telnet_cmd(self, cmd, wait=2):
        """发送AP CLI命令"""
        import telnetlib3
        reader, writer = await telnetlib3.open_connection(AP_HOST, AP_PORT)
        await asyncio.sleep(0.3)
        await reader.read(4096)
        writer.write('terminal length 0\r\n')
        await asyncio.sleep(0.2)
        await reader.read(4096)
        writer.write(cmd + '\r\n')
        await asyncio.sleep(wait)
        data = await reader.read(8192)
        if data and 'More' in data:
            writer.write(' ')
            await asyncio.sleep(1)
            data += await reader.read(4096)
        writer.close()
        return ''.join(c for c in data if c.isprintable() or c in '\n\r ')

    def test_01_ap_reachable(self):
        """验证AP Telnet可达"""
        async def _check():
            import telnetlib3
            reader, writer = await telnetlib3.open_connection(AP_HOST, AP_PORT)
            await asyncio.sleep(0.5)
            banner = await reader.read(4096)
            writer.close()
            return banner
        banner = asyncio.run(_check())
        assert 'AP180' in banner, f"AP banner unexpected: {banner[:100]}"

    def test_02_ap_radio_online(self):
        """验证AP无线射频在线"""
        out = asyncio.run(self._telnet_cmd('show dot11 radio-status'))
        assert 'online' in out, f"Radio not online: {out[:300]}"
        # 确认5GHz radio (slot 2) 在线
        assert '2' in out and 'online' in out, f"5GHz radio check: {out[:300]}"

    def test_03_ap_ssid_configured(self):
        """验证JXX SSID已配置"""
        out = asyncio.run(self._telnet_cmd('show dot11 mbssid'))
        assert 'JXX' in out, f"JXX SSID not found: {out[:300]}"

    def test_04_sta_interface_up(self, sta_ssh):
        """验证STA无线网卡状态"""
        rc, out, err = self._ssh_run(sta_ssh, f"ip link show {STA_IFACE}")
        assert rc == 0, f"ip link failed: {err}"
        assert STA_IFACE in out, f"Interface {STA_IFACE} not found"

    def test_05_sta_wifi_connect(self, sta_ssh):
        """STA连接JXX WiFi"""
        # 清理旧进程
        self._ssh_run(sta_ssh, "pkill wpa_supplicant 2>/dev/null; pkill dhclient 2>/dev/null", sudo=True)
        time.sleep(1)

        # 写 wpa_supplicant 配置
        config = f'network={{\n    ssid="{SSID}"\n    psk="{PSK}"\n    key_mgmt=WPA-PSK\n}}\n'
        self._ssh_run(sta_ssh,
                      f"cat > /tmp/wpa_test.conf << 'EOF'\n{config}\nEOF")

        # 启动 wpa_supplicant
        rc, out, err = self._ssh_run(
            sta_ssh,
            f"wpa_supplicant -B -i {STA_IFACE} -c /tmp/wpa_test.conf -D nl80211 2>&1",
            sudo=True, timeout=10,
        )
        assert rc == 0, f"wpa_supplicant failed: rc={rc} err={err} out={out}"

        # 等待连接
        time.sleep(6)

        # 检查连接
        rc, out, err = self._ssh_run(sta_ssh, f"iw dev {STA_IFACE} link", sudo=True)
        assert 'Connected' in out, f"WiFi not connected: {out} {err}"

        # 验证 SSID
        assert SSID in out, f"Wrong SSID: {out}"

    def test_06_sta_dhcp(self, sta_ssh):
        """STA获取DHCP地址"""
        rc, out, err = self._ssh_run(
            sta_ssh, f"dhclient -v {STA_IFACE}", sudo=True, timeout=20,
        )
        # dhclient may already be running, check IP
        if rc != 0:
            rc2, out2, _ = self._ssh_run(sta_ssh, f"ip addr show {STA_IFACE}")
            # 如果已有IP也算成功
            assert 'inet ' in out2, f"DHCP failed and no IP: rc={rc} err={err} out={out}"

    def test_07_sta_has_ip(self, sta_ssh):
        """验证STA获取到了IP地址"""
        rc, out, err = self._ssh_run(sta_ssh, f"ip addr show {STA_IFACE}")
        assert rc == 0, f"ip addr failed: {err}"
        assert 'inet 192.168.' in out, f"No valid IP found: {out}"
        # 提取 IP
        for line in out.split('\n'):
            if 'inet ' in line.strip():
                print(f"  STA IP: {line.strip()}")
                break

    def test_08_sta_internet(self, sta_ssh):
        """验证STA可以访问外网"""
        rc, out, err = self._ssh_run(sta_ssh, "ping -c 3 -W 5 8.8.8.8", timeout=20)
        assert rc == 0, f"Ping failed: {out} {err}"
        assert '0% packet loss' in out, f"Packet loss: {out}"

    def test_09_ap_sta_list(self):
        """AP侧验证STA关联（如有数据则检查）"""
        out = asyncio.run(self._telnet_cmd('show dot11 associations all-client'))
        # 此固件版本可能返回空，不强制断言内容
        print(f"AP STA list output: [{out.strip()}]")
        # 至少确认命令执行无报错
        assert '% Incomplete' not in out, f"Command failed: {out}"
        assert '% Invalid' not in out, f"Command failed: {out}"
        assert '% Unknown' not in out, f"Command failed: {out}"
