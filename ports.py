"""
TCP port reachability through the proxy (raw CONNECT, not requests).

Uses parse_proxy_parts from identity (same parts format as protocol check).
Port list comes from config.json.
"""

import base64
import json
import os
import socket

import socks

from identity import parse_proxy_parts

CONFIG_FILE = "config.json"

DEFAULT_PORT_TARGETS = [
    "smtp.gmail.com:25",
    "smtp.gmail.com:587",
    "smtp.gmail.com:465",
    "imap.gmail.com:993",
    "pop.gmail.com:995",
]
DEFAULT_PORT_TIMEOUT = 10


def load_port_targets() -> tuple[list[str], int]:
    """Load host:port list + timeout from config.json (or defaults)."""
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_PORT_TARGETS, DEFAULT_PORT_TIMEOUT

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as file:
            config = json.load(file)
        targets = config.get("port_targets", DEFAULT_PORT_TARGETS)
        timeout = int(config.get("port_timeout_sec", DEFAULT_PORT_TIMEOUT))
        return targets, timeout
    except Exception as e:
        print(f"[ports] could not read {CONFIG_FILE}: {e}")
        return DEFAULT_PORT_TARGETS, DEFAULT_PORT_TIMEOUT


def _connect_via_socks5(
    parts: dict, target_host: str, target_port: int, timeout: int
) -> bool:
    """Open a TCP tunnel to target through a SOCKS5 proxy."""
    sock = socks.socksocket()
    sock.settimeout(timeout)
    sock.set_proxy(
        socks.SOCKS5,
        parts["host"],
        int(parts["port"]),
        username=parts["user"],
        password=parts["password"],
    )
    try:
        sock.connect((target_host, target_port))
        return True
    finally:
        sock.close()


def _connect_via_http_proxy(
    parts: dict, target_host: str, target_port: int, timeout: int
) -> bool:
    """Open a TCP tunnel using HTTP CONNECT (raw socket)."""
    sock = socket.create_connection(
        (parts["host"], int(parts["port"])),
        timeout=timeout,
    )
    try:
        lines = [
            f"CONNECT {target_host}:{target_port} HTTP/1.1",
            f"Host: {target_host}:{target_port}",
        ]
        if parts["user"] and parts["password"]:
            token = base64.b64encode(
                f"{parts['user']}:{parts['password']}".encode()
            ).decode()
            lines.append(f"Proxy-Authorization: Basic {token}")

        request = "\r\n".join(lines) + "\r\n\r\n"
        sock.sendall(request.encode())

        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk

        status_line = response.split(b"\r\n", 1)[0].decode(errors="ignore")
        return " 200 " in status_line or status_line.endswith(" 200")
    finally:
        sock.close()


def check_ports(proxy_data: str, protocol: str | None) -> dict:
    """Try CONNECT to each config host:port; return reachable list."""
    result = {
        "reachable_ports": [],
    }

    if protocol is None:
        return result

    parts = parse_proxy_parts(proxy_data)
    if parts is None:
        return result

    targets, timeout = load_port_targets()
    reachable = []

    for target in targets:
        if ":" not in target:
            continue
        target_host, target_port_str = target.rsplit(":", 1)
        try:
            target_port = int(target_port_str)
        except ValueError:
            continue

        try:
            if protocol == "socks5":
                ok = _connect_via_socks5(parts, target_host, target_port, timeout)
            elif protocol in ("http", "https"):
                ok = _connect_via_http_proxy(parts, target_host, target_port, timeout)
            else:
                ok = False

            if ok:
                reachable.append(target)
        except Exception:
            continue

    result["reachable_ports"] = reachable
    return result
