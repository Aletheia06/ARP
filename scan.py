#!/usr/bin/env python3
"""扫描当前路由器下所有在线设备，显示 IP、MAC 和厂商"""
from scapy.all import Ether, ARP, srp, conf, get_if_addr, get_if_hwaddr
import sys

conf.verb = 0

# 常见 MAC 厂商前缀（前 6 位）
OUI = {
    "90fb5d": "TP-Link",
    "c470ab": "TP-Link",
    "18bb26": "Xiaomi",
    "88f4da": "Huawei",
    "d87cbb": "Huawei",
    "6e7242": "Apple",
    "2eea8a": "Apple",
    "dc567b": "Huawei",
    "24b2b9": "Xiaomi",
    "c6ffa1": "Unknown",
    "9af1a3": "Unknown",
    "029b52": "Raspberry Pi",
    "0015a5": "Samsung",
    "001e52": "Samsung",
    "0050b6": "Intel",
    "000c29": "VMware",
    "005056": "VMware",
    "000569": "VMware",
    "a886dd": "Apple",
    "bcee7b": "Apple",
    "f83dc6": "Realtek",
    "0003e7": "Intel",
    "001018": "Intel",
    "00241e": "Intel",
    "1c1b0d": "Intel",
    "08ed02": "Nintendo",
    "e03e8d": "Xiaomi",
    "ac853d": "Huawei",
    "a44cc8": "Xiaomi",
    "045168": "Huawei",
    "d423f1": "Apple",
    "000c6e": "Apple",
    "4ce676": "Apple",
    "703e4c": "ASUS",
    "022669": "Apple",
    "723209": "Apple",
    "72980a": "Unknown",
}

def lookup_vendor(mac):
    prefix = mac.replace(":", "")[:6].lower()
    return OUI.get(prefix, "Unknown")

try:
    my_ip = get_if_addr(conf.iface)
except Exception:
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    my_ip = s.getsockname()[0]
    s.close()

subnet = ".".join(my_ip.split(".")[:3])
print(f"本机 IP: {my_ip}")
print(f"本机 MAC: {get_if_hwaddr(conf.iface)}")
print(f"扫描网段: {subnet}.1/24")
print("=" * 60)

ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=f"{subnet}.1/24"),
             timeout=5, verbose=0)

print(f"\n发现 {len(ans)} 个设备:\n")
print(f"{'IP地址':<18}{'MAC地址':<20}{'厂商':<12}")
print("-" * 50)
devices = []
for _, rcv in ans:
    mac = rcv.hwsrc
    vendor = lookup_vendor(mac)
    devices.append((rcv.psrc, mac, vendor))
    if rcv.psrc == my_ip:
        devices[-1] = (rcv.psrc, mac, f"{vendor} <- 本机")

devices.sort(key=lambda x: [int(p) for p in x[0].split(".")[3:]])

for ip, mac, vendor in devices:
    print(f"{ip:<18}{mac:<20}{vendor:<12}")
print("=" * 60)
