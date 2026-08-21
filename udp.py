"""
UDP capability check through the proxy.

HTTP/HTTPS proxies cannot relay UDP → "n/a (http)".
SOCKS5 → real UDP ASSOCIATE + a small DNS query over UDP.
"""

import socket
import struct

from identity import parse_proxy_parts

UDP_TIMEOUT = 10
DNS_SERVER = ("8.8.8.8", 53)


def _build_dns_query(hostname: str) -> bytes:
    """Minimal DNS A-query packet for hostname."""
    transaction_id = b"\x12\x34"
    flags = b"\x01\x00"  # standard query, recursion desired
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question

    qname = b""
    for label in hostname.encode().split(b"."):
        qname += bytes([len(label)]) + label
    qname += b"\x00"

    qtype = b"\x00\x01"  # A
    qclass = b"\x00\x01"  # IN
    return transaction_id + flags + counts + qname + qtype + qclass


def _socks5_udp_associate_test(parts: dict, timeout: int = UDP_TIMEOUT) -> bool:
    """
    SOCKS5 UDP ASSOCIATE handshake, then send a DNS query via the UDP relay.

    Keep the TCP control connection open while UDP runs (SOCKS5 rule).
    """
    tcp = socket.create_connection(
        (parts["host"], int(parts["port"])),
        timeout=timeout,
    )
    tcp.settimeout(timeout)

    try:
        # 1) Greeting — offer no-auth and/or username/password
        if parts["user"] and parts["password"]:
            tcp.sendall(b"\x05\x02\x00\x02")
        else:
            tcp.sendall(b"\x05\x01\x00")

        greet = tcp.recv(2)
        if len(greet) < 2 or greet[0] != 5:
            return False

        method = greet[1]
        if method == 2:
            # Proxy asked for user/pass — we must have both, or fail safely
            if not parts["user"] or not parts["password"]:
                return False
            user = parts["user"].encode()
            password = parts["password"].encode()
            auth_req = bytes([1, len(user)]) + user + bytes([len(password)]) + password
            tcp.sendall(auth_req)
            auth_resp = tcp.recv(2)
            if len(auth_resp) < 2 or auth_resp[1] != 0:
                return False
        elif method != 0:
            return False

        # 2) UDP ASSOCIATE (CMD=0x03) to 0.0.0.0:0
        tcp.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        assoc = tcp.recv(256)
        if len(assoc) < 10 or assoc[1] != 0:
            return False

        atyp = assoc[3]
        if atyp == 1:  # IPv4
            relay_ip = socket.inet_ntoa(assoc[4:8])
            relay_port = struct.unpack("!H", assoc[8:10])[0]
        elif atyp == 3:  # domain
            length = assoc[4]
            relay_ip = assoc[5 : 5 + length].decode()
            relay_port = struct.unpack("!H", assoc[5 + length : 7 + length])[0]
        else:
            return False

        # Some proxies return 0.0.0.0 → use the proxy host instead
        if relay_ip in ("0.0.0.0", "::"):
            relay_ip = parts["host"]

        # 3) DNS query wrapped in SOCKS5 UDP header
        dns_payload = _build_dns_query("example.com")
        udp_header = (
            b"\x00\x00\x00\x01"
            + socket.inet_aton(DNS_SERVER[0])
            + struct.pack("!H", DNS_SERVER[1])
        )

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.settimeout(timeout)
        try:
            udp.sendto(udp_header + dns_payload, (relay_ip, relay_port))
            data, _addr = udp.recvfrom(4096)
            # Spec: any UDP reply through the relay = success (no deep DNS parse)
            return len(data) > 0
        finally:
            udp.close()
    finally:
        tcp.close()


def check_udp(proxy_data: str, protocol: str | None) -> dict:
    """
    Report whether the proxy can relay UDP.

    - http/https → "n/a (http)" (do not pretend to test)
    - socks5 → true/false after a real UDP ASSOCIATE + DNS probe
    """
    result = {
        "udp_supported": None,
    }

    if protocol is None:
        return result

    if protocol in ("http", "https"):
        result["udp_supported"] = "n/a (http)"
        return result

    if protocol != "socks5":
        return result

    parts = parse_proxy_parts(proxy_data)
    if parts is None:
        result["udp_supported"] = False
        return result

    try:
        ok = _socks5_udp_associate_test(parts)
        result["udp_supported"] = ok
    except Exception as e:
        print(f"[udp] SOCKS5 UDP test failed: {e}")
        result["udp_supported"] = False

    return result
