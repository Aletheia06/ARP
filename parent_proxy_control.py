#!/usr/bin/env python3
"""
Controllable local HTTP/HTTPS proxy for parental network control.

Usage:
  python parent_proxy_control.py serve
  python parent_proxy_control.py mode normal
  python parent_proxy_control.py mode slow
  python parent_proxy_control.py mode block

Set the child device Wi-Fi proxy to this PC's IP and port 8888.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlsplit


CONFIG_PATH = Path(__file__).with_name("parent_proxy_config.json")
BUFFER_SIZE = 4096
DEFAULT_CONFIG = {
    "listen_host": "0.0.0.0",
    "listen_port": 8888,
    "mode": "normal",
    "slow_kbps": 4,
    "block_message": "Network is paused by parent control.",
}


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        save_config(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)

    with CONFIG_PATH.open("r", encoding="utf-8") as file:
        data = json.load(file)

    config = dict(DEFAULT_CONFIG)
    config.update(data)
    return config


def save_config(config: dict) -> None:
    with CONFIG_PATH.open("w", encoding="utf-8") as file:
        json.dump(config, file, indent=2, ensure_ascii=False)
        file.write("\n")


def set_mode(mode: str) -> None:
    if mode not in {"normal", "slow", "block"}:
        raise SystemExit("Mode must be one of: normal, slow, block")

    config = load_config()
    config["mode"] = mode
    save_config(config)
    print(f"Mode changed to: {mode}")


def get_local_ips() -> list[str]:
    ips = set()
    try:
        hostname = socket.gethostname()
        for result in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(result[4][0])
    except OSError:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ips.add(sock.getsockname()[0])
    except OSError:
        pass

    return sorted(ip for ip in ips if not ip.startswith("127."))


def copy_with_limit(source: socket.socket, target: socket.socket, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            data = source.recv(BUFFER_SIZE)
            if not data:
                break

            config = load_config()
            mode = config.get("mode", "normal")

            if mode == "block":
                break

            target.sendall(data)

            if mode == "slow":
                slow_kbps = max(float(config.get("slow_kbps", 4)), 0.1)
                bytes_per_second = slow_kbps * 1024
                time.sleep(len(data) / bytes_per_second)
        except (ConnectionError, OSError):
            break

    stop.set()
    for sock in (source, target):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        config = load_config()
        mode = config.get("mode", "normal")
        sys.stderr.write(f"[{mode}] {self.client_address[0]} - {fmt % args}\n")

    def do_CONNECT(self) -> None:
        config = load_config()
        if config.get("mode") == "block":
            self.send_error(403, config.get("block_message", "Blocked"))
            return

        host, port = self.parse_connect_target()
        if not host:
            self.send_error(400, "Bad CONNECT target")
            return

        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            self.send_error(502, f"Cannot connect: {exc}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        stop = threading.Event()
        upstream = threading.Thread(target=copy_with_limit, args=(self.connection, remote, stop))
        downstream = threading.Thread(target=copy_with_limit, args=(remote, self.connection, stop))
        upstream.start()
        downstream.start()
        upstream.join()
        downstream.join()

    def do_GET(self) -> None:
        self.forward_plain_http()

    def do_POST(self) -> None:
        self.forward_plain_http()

    def do_PUT(self) -> None:
        self.forward_plain_http()

    def do_DELETE(self) -> None:
        self.forward_plain_http()

    def do_HEAD(self) -> None:
        self.forward_plain_http()

    def do_OPTIONS(self) -> None:
        self.forward_plain_http()

    def do_PATCH(self) -> None:
        self.forward_plain_http()

    def parse_connect_target(self) -> tuple[str | None, int]:
        target = self.path.strip()
        if ":" not in target:
            return None, 443
        host, port_text = target.rsplit(":", 1)
        try:
            return host, int(port_text)
        except ValueError:
            return None, 443

    def forward_plain_http(self) -> None:
        config = load_config()
        if config.get("mode") == "block":
            message = config.get("block_message", "Blocked").encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(message)
            return

        parsed = urlsplit(self.path)
        host = parsed.hostname or self.headers.get("Host", "").split(":")[0]
        port = parsed.port or 80
        if not host:
            self.send_error(400, "Missing host")
            return

        path = self.path
        if parsed.scheme and parsed.netloc:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

        body = b""
        content_length = self.headers.get("Content-Length")
        if content_length:
            body = self.rfile.read(int(content_length))

        request_lines = [f"{self.command} {path} HTTP/1.1"]
        for key, value in self.headers.items():
            if key.lower() not in {"proxy-connection", "connection"}:
                request_lines.append(f"{key}: {value}")
        request_lines.append("Connection: close")
        request_lines.append("")
        request_lines.append("")
        request_data = "\r\n".join(request_lines).encode("iso-8859-1") + body

        try:
            with socket.create_connection((host, port), timeout=10) as remote:
                remote.sendall(request_data)
                self.stream_plain_response(remote)
        except OSError as exc:
            self.send_error(502, f"Cannot connect: {exc}")

    def stream_plain_response(self, remote: socket.socket) -> None:
        while True:
            readable, _, _ = select.select([remote], [], [], 30)
            if not readable:
                break

            data = remote.recv(BUFFER_SIZE)
            if not data:
                break

            self.connection.sendall(data)

            config = load_config()
            if config.get("mode") == "slow":
                slow_kbps = max(float(config.get("slow_kbps", 4)), 0.1)
                time.sleep(len(data) / (slow_kbps * 1024))
            elif config.get("mode") == "block":
                break


def serve() -> None:
    config = load_config()
    host = config.get("listen_host", "0.0.0.0")
    port = int(config.get("listen_port", 8888))

    print("Parent proxy control is running.")
    print(f"Proxy address: {host}:{port}")
    for ip in get_local_ips():
        print(f"Child device proxy can use: {ip}:{port}")
    print("Switch modes in another terminal:")
    print("  python parent_proxy_control.py mode normal")
    print("  python parent_proxy_control.py mode slow")
    print("  python parent_proxy_control.py mode block")
    print("Press Ctrl+C to stop.")

    with ThreadingTCPServer((host, port), ProxyHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Controllable local HTTP/HTTPS proxy")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("serve", help="Start proxy server")

    mode_parser = subparsers.add_parser("mode", help="Set proxy mode")
    mode_parser.add_argument("value", choices=["normal", "slow", "block"])

    args = parser.parse_args()

    if args.command == "serve":
        serve()
    elif args.command == "mode":
        set_mode(args.value)


if __name__ == "__main__":
    main()
