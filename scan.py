#!/usr/bin/env python3
"""Scan the LAN for online devices and show IP, MAC, vendor, hostname, type and alias."""

from __future__ import annotations

import argparse
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from scapy.all import ARP, Ether, conf, get_if_addr, get_if_hwaddr, get_if_list, srp


conf.verb = 0

CACHE_PATH = Path(__file__).with_name(".oui_cache.json")
ALIASES_PATH = Path(__file__).with_name("scan_aliases.json")
CACHE_TTL_SECONDS = 30 * 24 * 60 * 60

FALLBACK_OUI = {
    "90fb5d": "TP-Link",
    "c470ab": "TP-Link",
    "18bb26": "Xiaomi",
    "88f4da": "Huawei",
    "d87cbb": "Huawei",
    "dc567b": "Huawei",
    "24b2b9": "Xiaomi",
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
    "703e4c": "ASUSTek COMPUTER INC.",
    "08ed02": "Nintendo",
}

HOSTNAME_TYPE_HINTS = (
    ("iphone", "iPhone"),
    ("ipad", "iPad"),
    ("macbook", "MacBook"),
    ("imac", "iMac"),
    ("airpods", "Apple audio"),
    ("android", "Android device"),
    ("huawei", "Huawei device"),
    ("honor", "Honor device"),
    ("xiaomi", "Xiaomi device"),
    ("redmi", "Xiaomi phone"),
    ("mi-", "Xiaomi device"),
    ("router", "Router"),
    ("gateway", "Router"),
    ("openwrt", "Router"),
    ("ap", "Access point"),
    ("printer", "Printer"),
    ("hp-", "Printer"),
    ("epson", "Printer"),
    ("canon", "Printer"),
    ("camera", "Camera"),
    ("cam", "Camera"),
    ("hik", "Camera"),
    ("dahua", "Camera"),
    ("tv", "TV"),
    ("bravia", "TV"),
    ("nas", "NAS"),
    ("synology", "NAS"),
    ("desktop", "Windows PC"),
    ("laptop", "Laptop"),
    ("thinkpad", "Laptop"),
    ("surface", "Laptop"),
    ("vmware", "Virtual machine"),
)

VENDOR_TYPE_HINTS = (
    ("apple", "Apple device"),
    ("samsung", "Samsung device"),
    ("nintendo", "Game console"),
    ("raspberry", "Single-board computer"),
    ("vmware", "Virtual machine"),
    ("intel", "Computer/PC"),
    ("realtek", "Computer/PC"),
    ("tp-link", "Router/IoT"),
    ("asustek", "Router/PC"),
    ("asus", "Router/PC"),
    ("huawei", "Huawei device"),
    ("xiaomi", "Xiaomi device"),
)

PING_HOST_RE = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9_.-]{0,253})\s*\[(\d{1,3}(?:\.\d{1,3}){3})\]"
)
NBTSTAT_NAME_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]{0,253})\s+<00>\s+UNIQUE",
    re.IGNORECASE,
)


def normalize_mac(mac: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", mac).lower()


def normalize_prefix(mac: str) -> str:
    return normalize_mac(mac)[:6]


def load_aliases() -> dict[str, dict[str, str]]:
    aliases = {"mac": {}, "ip": {}, "hostname": {}}
    if not ALIASES_PATH.exists():
        return aliases

    try:
        raw = json.loads(ALIASES_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[warn] cannot read {ALIASES_PATH.name}: {exc}", file=sys.stderr)
        return aliases

    for key in aliases:
        section = raw.get(key, {})
        if not isinstance(section, dict):
            continue
        if key == "mac":
            aliases[key] = {normalize_mac(k): str(v) for k, v in section.items()}
        else:
            aliases[key] = {str(k).lower(): str(v) for k, v in section.items()}
    return aliases


def save_oui_cache(vendors: dict[str, str]) -> None:
    payload = {"updated_at": int(time.time()), "vendors": vendors}
    CACHE_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_oui_data(refresh: bool) -> dict[str, str]:
    vendors = dict(FALLBACK_OUI)

    if CACHE_PATH.exists():
        try:
            cache = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            updated_at = int(cache.get("updated_at", 0))
            if not refresh and time.time() - updated_at <= CACHE_TTL_SECONDS:
                cached_vendors = cache.get("vendors", {})
                if isinstance(cached_vendors, dict):
                    vendors.update(
                        {
                            str(prefix).lower(): str(name)
                            for prefix, name in cached_vendors.items()
                        }
                    )
                    return vendors
        except (json.JSONDecodeError, OSError, ValueError):
            pass

    try:
        if getattr(conf, "manufdb", None) is not None:
            scapy_vendors = {
                prefix.lower().replace(":", ""): long_name or short_name
                for prefix, (short_name, long_name) in conf.manufdb.d.items()
            }
            if scapy_vendors:
                vendors.update(scapy_vendors)
                save_oui_cache(scapy_vendors)
    except Exception as exc:
        print(f"[warn] failed to load Scapy vendor DB, using builtin/cache: {exc}", file=sys.stderr)

    return vendors


def interface_priority(iface: str, ip_obj: ipaddress.IPv4Address) -> tuple[int, int]:
    name = iface.lower()
    score = 0
    if ip_obj.is_private:
        score += 100
    if any(word in name for word in ("wi-fi", "wlan", "wireless", "ethernet")):
        score += 30
    if any(word in name for word in ("docker", "wsl", "vmware", "virtual", "hyper-v", "vbox")):
        score -= 40
    if str(conf.iface).lower() == name:
        score += 10
    return score, len(name)


def iter_ipv4_interfaces() -> list[tuple[str, str, ipaddress.IPv4Address]]:
    candidates = []
    seen_ips = set()
    for iface in get_if_list():
        try:
            ip_text = get_if_addr(iface)
        except Exception:
            continue
        if not ip_text or ip_text in {"0.0.0.0"} or ip_text.startswith("127."):
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if ip_obj.version != 4 or ip_text in seen_ips:
            continue
        seen_ips.add(ip_text)
        candidates.append((iface, ip_text, ip_obj))
    return candidates


def choose_scan_target(subnet_arg: str | None) -> tuple[str, str, ipaddress.IPv4Network]:
    candidates = iter_ipv4_interfaces()
    if not candidates:
        raise RuntimeError("no usable IPv4 interface found")

    default_route_ip = resolve_default_route_interface_ip()
    if default_route_ip:
        for iface, ip_text, _ in candidates:
            if ip_text == default_route_ip:
                if subnet_arg:
                    return iface, ip_text, ipaddress.ip_network(subnet_arg, strict=False)
                return iface, ip_text, ipaddress.ip_network(f"{ip_text}/24", strict=False)

    candidates.sort(key=lambda item: interface_priority(item[0], item[2]), reverse=True)

    if subnet_arg:
        network = ipaddress.ip_network(subnet_arg, strict=False)
        for iface, ip_text, ip_obj in candidates:
            if ip_obj in network:
                return iface, ip_text, network
        iface, ip_text, _ = candidates[0]
        return iface, ip_text, network

    iface, ip_text, _ = candidates[0]
    network = ipaddress.ip_network(f"{ip_text}/24", strict=False)
    return iface, ip_text, network


def resolve_gateway_ip() -> str:
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=5,
                check=False,
            )
            for line in result.stdout.splitlines():
                match = re.search(
                    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})",
                    line,
                )
                if match:
                    return match.group(1)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return ""


def resolve_default_route_interface_ip() -> str:
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=5,
                check=False,
            )
            for line in result.stdout.splitlines():
                match = re.search(
                    r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)",
                    line,
                )
                if match and match.group(1) != "198.18.0.2":
                    return match.group(2)
        except (OSError, subprocess.TimeoutExpired):
            pass
    return ""


def resolve_hostname_with_ping(ip: str) -> str:
    try:
        result = subprocess.run(
            ["ping", "-a", "-n", "1", "-w", "600", ip],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""

    for line in result.stdout.splitlines():
        match = PING_HOST_RE.search(line)
        if match and match.group(2) == ip:
            return match.group(1)
    return ""


def resolve_hostname_with_nbtstat(ip: str) -> str:
    try:
        result = subprocess.run(
            ["nbtstat", "-A", ip],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""

    for line in result.stdout.splitlines():
        match = NBTSTAT_NAME_RE.search(line)
        if match:
            name = match.group(1).strip()
            if name and name.upper() != "WORKGROUP":
                return name
    return ""


def resolve_hostname(ip: str) -> str:
    """OS-level reverse lookups only. NOT thread-safe with scapy, but these calls are,
    so this is what runs inside the thread pool."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    host = resolve_hostname_with_ping(ip)
    if host:
        return host

    if platform.system() == "Windows":
        return resolve_hostname_with_nbtstat(ip)
    return ""


def mdns_reverse_lookup(ips: list[str], iface: str, timeout: float = 2.0) -> dict[str, str]:
    """Resolve .local names via mDNS (Bonjour) for many IPs at once.

    Phones (iOS/Android) ignore reverse-DNS and NetBIOS but answer mDNS. This sends
    one reverse-PTR query per IP, then sniffs all replies in a SINGLE main-thread
    session -- scapy is not thread-safe, so we must never do this from a thread pool.
    """
    result: dict[str, str] = {}
    if not ips:
        return result
    try:
        from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, AsyncSniffer, sendp
    except Exception:
        return result

    try:
        sniffer = AsyncSniffer(iface=iface, filter="udp port 5353", store=True)
        sniffer.start()
    except Exception:
        return result

    time.sleep(0.2)
    for ip in ips:
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        # The top bit of qclass is the QU (unicast-response) flag, so devices reply directly.
        query = (
            Ether(dst="01:00:5e:00:00:fb")
            / IP(dst="224.0.0.251")
            / UDP(sport=5353, dport=5353)
            / DNS(rd=0, qd=DNSQR(qname=rev, qtype="PTR", qclass=0x8001))
        )
        try:
            sendp(query, iface=iface, verbose=0)
        except Exception:
            pass

    time.sleep(timeout)
    try:
        packets = sniffer.stop()
    except Exception:
        return result

    for pkt in packets or []:
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        for i in range(dns.ancount or 0):
            try:
                rr = dns.an[i]
            except (IndexError, TypeError):
                break
            if not isinstance(rr, DNSRR) or rr.type != 12:  # 12 == PTR
                continue
            rrname = rr.rrname
            if isinstance(rrname, bytes):
                rrname = rrname.decode("utf-8", "ignore")
            labels = rrname.rstrip(".").split(".")
            if len(labels) < 6 or labels[-2:] != ["in-addr", "arpa"]:
                continue
            ip = ".".join(reversed(labels[:4]))
            name = rr.rdata
            if isinstance(name, bytes):
                name = name.decode("utf-8", "ignore")
            name = name.rstrip(".")
            if name:
                result[ip] = name
    return result


def lookup_vendor(mac: str, vendors: dict[str, str]) -> str:
    prefix = normalize_prefix(mac)
    vendor = vendors.get(prefix)
    if vendor:
        return vendor

    manufdb = getattr(conf, "manufdb", None)
    if manufdb is not None:
        try:
            resolved = manufdb._get_manuf(mac)
            if resolved and resolved != mac:
                return resolved
        except Exception:
            pass

    return "Unknown"


def lookup_alias(ip: str, mac: str, hostname: str, aliases: dict[str, dict[str, str]]) -> str:
    return (
        aliases["mac"].get(normalize_mac(mac))
        or aliases["ip"].get(ip.lower())
        or aliases["hostname"].get(hostname.lower())
        or ""
    )


def infer_device_type(
    ip: str,
    vendor: str,
    hostname: str,
    alias: str,
    my_ip: str,
    gateway_ip: str,
) -> str:
    if ip == my_ip:
        return "This PC"
    if gateway_ip and ip == gateway_ip:
        return "Router/Gateway"

    lowered_host = hostname.lower()
    lowered_vendor = vendor.lower()
    lowered_alias = alias.lower()

    for keyword, device_type in HOSTNAME_TYPE_HINTS:
        if keyword in lowered_host or keyword in lowered_alias:
            return device_type

    if ip.endswith(".1") and any(
        brand in lowered_vendor for brand in ("tp-link", "huawei", "xiaomi", "asus")
    ):
        return "Router"

    for keyword, device_type in VENDOR_TYPE_HINTS:
        if keyword in lowered_vendor:
            return device_type

    return "Unknown"


def finalize_device(
    device: dict[str, str],
    aliases: dict[str, dict[str, str]],
    my_ip: str,
    gateway_ip: str,
) -> None:
    """Refresh alias and type from the (possibly newly resolved) hostname."""
    ip, mac, hostname = device["ip"], device["mac"], device["hostname"]
    alias = lookup_alias(ip, mac, hostname, aliases)
    if ip == my_ip and alias:
        alias = f"{alias} (this PC)"
    elif ip == my_ip:
        alias = "this PC"
    device["alias"] = alias
    device["device_type"] = infer_device_type(
        ip, device["vendor"], hostname, alias, my_ip, gateway_ip
    )


def ipv4_sort_key(item: dict[str, str]) -> tuple:
    """Sort by IPv4; IPv6-only devices (no dotted-quad IP) go last."""
    try:
        return (0,) + tuple(int(part) for part in item["ip"].split("."))
    except ValueError:
        return (1, 0, 0, 0, 0)


def scan_network(iface: str, network: ipaddress.IPv4Network, timeout: float) -> list:
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
        iface=iface,
        timeout=timeout,
        verbose=0,
    )
    return list(ans)


def ping_ipv6_all_nodes(iface: str, timeout: float) -> None:
    """Ping the all-nodes multicast address ff02::1 to wake devices and fill our
    IPv6 neighbor table. Phones usually prefer IPv6, so plain ARP can't see them."""
    try:
        from scapy.all import IPv6, ICMPv6EchoRequest
    except Exception:
        return
    try:
        srp(
            Ether(dst="33:33:00:00:00:01")
            / IPv6(dst="ff02::1")
            / ICMPv6EchoRequest(),
            iface=iface,
            timeout=timeout,
            verbose=0,
        )
    except Exception:
        pass


def read_ipv6_neighbors() -> dict[str, list[str]]:
    """Read the system IPv6 neighbor table -> {normalized_mac: [ipv6, ...]}. Windows only."""
    neighbors: dict[str, list[str]] = {}
    if platform.system() != "Windows":
        return neighbors

    try:
        result = subprocess.run(
            ["netsh", "interface", "ipv6", "show", "neighbors"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=8,
            check=False,
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
        addr, mac, state = match.group(1), match.group(2), match.group(3).lower()
        if state in {"unreachable", "incomplete"}:
            continue
        addr = addr.split("%")[0]  # drop the zone id, e.g. fe80::1%14
        if addr.startswith("ff") or addr in {"::", "::1"}:
            continue  # skip multicast / unspecified
        neighbors.setdefault(normalize_mac(mac), []).append(addr)
    return neighbors


def merge_ipv6(devices: list[dict[str, str]], neighbors: dict[str, list[str]]) -> None:
    """Merge IPv6 addresses into the device list by MAC; add IPv6-only devices too."""
    by_mac = {normalize_mac(item["mac"]): item for item in devices}
    for mac, addrs in neighbors.items():
        # Prefer showing global addresses before link-local fe80:: ones.
        addrs_sorted = sorted(addrs, key=lambda a: a.lower().startswith("fe80"))
        if mac in by_mac:
            by_mac[mac]["ipv6"] = ", ".join(addrs_sorted)
        else:
            devices.append(
                {
                    "ip": "(IPv6 only)",
                    "mac": ":".join(mac[i : i + 2] for i in range(0, 12, 2)),
                    "vendor": "Unknown",
                    "hostname": "",
                    "alias": "",
                    "device_type": "Unknown",
                    "ipv6": ", ".join(addrs_sorted),
                }
            )


def print_devices(devices: list[dict[str, str]]) -> None:
    headers = ("No.", "IP", "MAC", "Vendor", "Hostname", "Type", "IPv6", "Note")
    rows = [
        (
            str(index),
            item["ip"],
            item["mac"],
            item["vendor"],
            item["hostname"] or "-",
            item["device_type"],
            item.get("ipv6") or "-",
            item["alias"] or "-",
        )
        for index, item in enumerate(devices, 1)
    ]

    widths = [len(title) for title in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = min(max(widths[index], len(value)), 39)

    line_format = "  ".join(f"{{:<{width}}}" for width in widths)
    print(line_format.format(*headers))
    print("-" * (sum(widths) + 10))
    for row in rows:
        print(line_format.format(*row))


def resolve_selected_devices(
    devices: list[dict[str, str]],
    aliases: dict[str, dict[str, str]],
    my_ip: str,
    gateway_ip: str,
    iface: str,
) -> None:
    if not devices:
        return

    print("\nEnter device numbers to resolve hostnames (e.g. 1,3,5). Empty line to finish.")
    while True:
        selection = input("numbers: ").strip()
        if not selection:
            return

        selected_indexes: list[int] = []
        for part in re.split(r"[,\s]+", selection):
            if not part:
                continue
            if not part.isdigit():
                print(f"ignoring invalid input: {part}")
                continue
            index = int(part)
            if index < 1 or index > len(devices):
                print(f"out of range: {index}")
                continue
            selected_indexes.append(index)

        if not selected_indexes:
            continue

        to_resolve = [devices[i - 1] for i in dict.fromkeys(selected_indexes)]
        # One mDNS batch for the whole selection (catches phones), then OS fallbacks.
        mdns_names = mdns_reverse_lookup([d["ip"] for d in to_resolve], iface)
        for device in to_resolve:
            print(f"resolving {device['ip']} ...")
            name = mdns_names.get(device["ip"]) or resolve_hostname(device["ip"])
            device["hostname"] = name
            finalize_device(device, aliases, my_ip, gateway_ip)
            print(f"  {device['ip']} -> {name or 'not found'}")

        print()
        print_devices(devices)
        print("=" * 96)


def warn_if_proxy_arp(devices: list[dict[str, str]], network: ipaddress.IPv4Network) -> None:
    mac_counts: dict[str, int] = {}
    for item in devices:
        mac_counts[item["mac"]] = mac_counts.get(item["mac"], 0) + 1

    repeated = [(mac, count) for mac, count in mac_counts.items() if count >= 8]
    if repeated and not network.is_private:
        mac, count = max(repeated, key=lambda item: item[1])
        print(
            f"[warn] this looks like a public/ISP subnet: MAC {mac} answered for {count} IPs.",
            file=sys.stderr,
        )
        print(
            "[warn] that is usually not a home LAN. Use --subnet 192.168.x.0/24 to pick your home range.",
            file=sys.stderr,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan the LAN and identify devices.")
    parser.add_argument("--subnet", help="subnet to scan, e.g. 192.168.0.0/24")
    parser.add_argument("--timeout", type=float, default=5.0, help="ARP wait time, default 5s")
    parser.add_argument(
        "--resolve-names",
        action="store_true",
        help="also resolve hostnames (mDNS + reverse DNS + NetBIOS)",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="quick scan first, then resolve names by number on demand",
    )
    parser.add_argument(
        "--refresh-oui",
        action="store_true",
        help="force-refresh the local vendor cache",
    )
    return parser


def resolve_all_hostnames(devices: list[dict[str, str]], iface: str) -> None:
    """Fill in hostnames for every device. mDNS runs once on the main thread; the
    remaining OS lookups run in a thread pool (those calls ARE thread-safe)."""
    mdns_names = mdns_reverse_lookup([d["ip"] for d in devices], iface)
    for device in devices:
        if mdns_names.get(device["ip"]):
            device["hostname"] = mdns_names[device["ip"]]

    rest = [d for d in devices if not d["hostname"]]
    if not rest:
        return
    with ThreadPoolExecutor(max_workers=min(16, len(rest))) as pool:
        names = pool.map(lambda d: resolve_hostname(d["ip"]), rest)
    for device, name in zip(rest, names):
        device["hostname"] = name


def main() -> int:
    args = build_parser().parse_args()
    vendors = load_oui_data(refresh=args.refresh_oui)
    aliases = load_aliases()

    try:
        iface, my_ip, network = choose_scan_target(args.subnet)
    except Exception as exc:
        print(f"[error] cannot determine scan interface/subnet: {exc}", file=sys.stderr)
        return 1

    try:
        my_mac = get_if_hwaddr(iface)
    except Exception:
        my_mac = "Unknown"

    gateway_ip = resolve_gateway_ip()

    print(f"Interface: {iface}")
    print(f"My IP:     {my_ip}")
    print(f"My MAC:    {my_mac}")
    print(f"Subnet:    {network}")
    if gateway_ip:
        print(f"Gateway:   {gateway_ip}")
    print("=" * 96)

    replies = scan_network(iface, network, args.timeout)
    devices: list[dict[str, str]] = []
    seen_ips = set()

    for _, received in replies:
        ip = received.psrc
        if ip in seen_ips:
            continue
        if ip == str(network.network_address) or ip == str(network.broadcast_address):
            continue
        seen_ips.add(ip)

        mac = received.hwsrc
        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": lookup_vendor(mac, vendors),
                "hostname": "",
                "alias": "",
                "device_type": "",
                "ipv6": "",
            }
        )

    if args.resolve_names and devices:
        resolve_all_hostnames(devices, iface)

    for device in devices:
        finalize_device(device, aliases, my_ip, gateway_ip)

    # Merge IPv6: phones usually prefer IPv6, so ARP alone neither sees nor limits them.
    ping_ipv6_all_nodes(iface, min(args.timeout, 3.0))
    merge_ipv6(devices, read_ipv6_neighbors())

    devices.sort(key=ipv4_sort_key)

    print(f"\nFound {len(devices)} device(s)\n")
    if devices:
        print_devices(devices)
        print("=" * 96)
        warn_if_proxy_arp(devices, network)
    else:
        print("No devices found.")

    if not ALIASES_PATH.exists():
        print(
            f"\nTip: create {ALIASES_PATH.name} to give known devices friendly names.",
        )

    if args.interactive and devices:
        resolve_selected_devices(devices, aliases, my_ip, gateway_ip, iface)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
