#!/usr/bin/env python3
"""扫描局域网在线设备，显示 IP、MAC、厂商、主机名、设备类型和自定义别名。"""

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
        print(f"[warn] 无法读取 {ALIASES_PATH.name}: {exc}", file=sys.stderr)
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
        print(f"[warn] 载入 Scapy 厂商库失败，改用内置表/缓存: {exc}", file=sys.stderr)

    return vendors


def interface_priority(iface: str, ip_obj: ipaddress.IPv4Address) -> tuple[int, int]:
    name = iface.lower()
    score = 0
    if ip_obj.is_private:
        score += 100
    if any(word in name for word in ("wi-fi", "wlan", "wireless", "ethernet", "以太网")):
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
        raise RuntimeError("没有找到可用的 IPv4 网卡")

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


def scan_network(iface: str, network: ipaddress.IPv4Network, timeout: float) -> list:
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
        iface=iface,
        timeout=timeout,
        verbose=0,
    )
    return list(ans)


def print_devices(devices: list[dict[str, str]]) -> None:
    headers = ("序号", "IP地址", "MAC地址", "厂商", "主机名", "设备类型", "备注")
    rows = [
        (
            str(index),
            item["ip"],
            item["mac"],
            item["vendor"],
            item["hostname"] or "-",
            item["device_type"],
            item["alias"] or "-",
        )
        for index, item in enumerate(devices, 1)
    ]

    widths = [len(title) for title in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = min(max(widths[index], len(value)), 34)

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
) -> None:
    if not devices:
        return

    print("\n输入设备序号查询主机名；可输入多个序号，例如 1,3,5；直接回车结束。")
    while True:
        selection = input("要查询的序号: ").strip()
        if not selection:
            return

        selected_indexes: list[int] = []
        for part in re.split(r"[,\s，]+", selection):
            if not part:
                continue
            if not part.isdigit():
                print(f"忽略无效输入: {part}")
                continue
            index = int(part)
            if index < 1 or index > len(devices):
                print(f"序号超出范围: {index}")
                continue
            selected_indexes.append(index)

        if not selected_indexes:
            continue

        for index in dict.fromkeys(selected_indexes):
            device = devices[index - 1]
            print(f"正在查询 #{index} {device['ip']} ...")
            hostname = resolve_hostname(device["ip"])
            device["hostname"] = hostname
            device["alias"] = lookup_alias(device["ip"], device["mac"], hostname, aliases)
            if device["ip"] == my_ip and device["alias"]:
                device["alias"] = f"{device['alias']} (本机)"
            elif device["ip"] == my_ip:
                device["alias"] = "本机"
            device["device_type"] = infer_device_type(
                device["ip"],
                device["vendor"],
                hostname,
                device["alias"],
                my_ip,
                gateway_ip,
            )
            print(f"#{index} 主机名: {hostname or '未获取到'}")

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
            f"[warn] 当前扫描的是公网/运营商网段，MAC {mac} 同时响应了 {count} 个 IP。",
            file=sys.stderr,
        )
        print(
            "[warn] 这通常不是家庭局域网设备列表，建议使用 --subnet 192.168.x.0/24 指定家庭网段。",
            file=sys.stderr,
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="扫描局域网在线设备并尽量识别设备信息")
    parser.add_argument("--subnet", help="手动指定网段，例如 192.168.0.0/24")
    parser.add_argument("--timeout", type=float, default=5.0, help="ARP 等待时间，默认 5 秒")
    parser.add_argument(
        "--resolve-names",
        action="store_true",
        help="额外反查主机名，可能明显变慢",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="先快速扫描，再按序号选择设备查询主机名",
    )
    parser.add_argument(
        "--refresh-oui",
        action="store_true",
        help="强制刷新本地厂商缓存",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    vendors = load_oui_data(refresh=args.refresh_oui)
    aliases = load_aliases()

    try:
        iface, my_ip, network = choose_scan_target(args.subnet)
    except Exception as exc:
        print(f"[error] 无法确定扫描网卡/网段: {exc}", file=sys.stderr)
        return 1

    try:
        my_mac = get_if_hwaddr(iface)
    except Exception:
        my_mac = "Unknown"

    gateway_ip = resolve_gateway_ip()

    print(f"使用网卡: {iface}")
    print(f"本机 IP: {my_ip}")
    print(f"本机 MAC: {my_mac}")
    print(f"扫描网段: {network}")
    if gateway_ip:
        print(f"默认网关: {gateway_ip}")
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
        vendor = lookup_vendor(mac, vendors)
        hostname = resolve_hostname(ip) if args.resolve_names else ""
        alias = lookup_alias(ip, mac, hostname, aliases)
        device_type = infer_device_type(ip, vendor, hostname, alias, my_ip, gateway_ip)

        if ip == my_ip and alias:
            alias = f"{alias} (本机)"
        elif ip == my_ip:
            alias = "本机"

        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "alias": alias,
                "device_type": device_type,
            }
        )

    devices.sort(key=lambda item: tuple(int(part) for part in item["ip"].split(".")))

    print(f"\n发现 {len(devices)} 个设备\n")
    if devices:
        print_devices(devices)
        print("=" * 96)
        warn_if_proxy_arp(devices, network)
    else:
        print("没有发现设备。")

    if not ALIASES_PATH.exists():
        print(
            f"\n提示: 可以新建 {ALIASES_PATH.name} 给已知设备起别名，便于下次直接识别。",
        )

    if args.interactive and devices:
        resolve_selected_devices(devices, aliases, my_ip, gateway_ip)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
