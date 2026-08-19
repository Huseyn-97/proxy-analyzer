"""
Identity checks (formerly measure.py core):
  - get_real_ip
  - check_anonymity
  - check_protocol

Helpers used only by protocol live here too.
"""

import requests

LEAK_HEADERS = ("X-Forwarded-For", "Forwarded", "X-Real-IP")
PROXY_REVEAL_HEADERS = ("Via",)

LATENCY_URL = "https://api.ipify.org?format=json"

PROTOCOLS_TO_TRY = ("socks5", "http", "https")

# Order matters: "https://" before "http://"
PROTOCOL_PREFIXES = (
    ("socks5://", "socks5"),
    ("https://", "https"),
    ("http://", "http"),
)


def get_real_ip() -> str | None:
    """Fetch THIS machine's public IP directly (no proxy)."""
    services = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/all.json",
        "https://ipinfo.io/json",
    ]
    for url in services:
        try:
            response = requests.get(url, timeout=10)  # proxies= No
            response.raise_for_status()
            data = response.json()
            ip = data.get("ip") or data.get("ip_addr")
            if ip:
                return ip
        except Exception:
            continue
    print("[identity] could not get real IP from any service")
    return None


def check_anonymity(proxy_dict: dict, real_ip: str) -> dict:
    """Reads headers over the proxy and determines anonymity."""
    result = {
        "anonymity_level": None,
        "leaked_headers": [],
    }

    if real_ip is None or proxy_dict is None:
        return result

    try:
        response = requests.get(
            "https://httpbin.org/headers",
            proxies=proxy_dict,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        headers = data.get("headers", {})
    except Exception as e:
        print(f"[identity] anonymity check failed: {e}")
        return result

    headers_lower = {}
    for key, value in headers.items():
        headers_lower[key.lower()] = value

    leaked = []
    for name in LEAK_HEADERS:
        value = headers_lower.get(name.lower(), "")
        if value != "" and real_ip in value:
            leaked.append(name)

    reveals_proxy = False
    for name in PROXY_REVEAL_HEADERS:
        value = headers_lower.get(name.lower(), "")
        if value != "":
            reveals_proxy = True
            break

    result["leaked_headers"] = leaked

    if len(leaked) > 0:
        result["anonymity_level"] = "transparent"
    elif reveals_proxy:
        result["anonymity_level"] = "anonymous"
    else:
        result["anonymity_level"] = "elite"

    return result


def parse_proxy_parts(proxy_data: str) -> dict | None:
    """Split proxy string into claimed/host/port/user/password."""
    if not proxy_data:
        return None

    claimed = "http"
    rest = proxy_data
    for prefix, name in PROTOCOL_PREFIXES:
        if rest.startswith(prefix):
            claimed = name
            rest = rest[len(prefix) :]
            break

    user = None
    password = None

    if "@" in rest:
        credentials, address = rest.split("@", 1)
        user, password = credentials.split(":", 1)
        host, port = address.split(":")
    else:
        parts = rest.split(":")
        if len(parts) == 2:
            host, port = parts[0], parts[1]
        elif len(parts) == 4:
            host, port = parts[0], parts[1]
            user, password = parts[2], parts[3]
        else:
            return None

    return {
        "claimed": claimed,
        "host": host,
        "port": port,
        "user": user,
        "password": password,
    }


def build_proxy_dict(scheme: str, parts: dict) -> dict:
    """Build requests proxies= dict for one scheme."""
    if parts["user"] and parts["password"]:
        auth = f"{parts['user']}:{parts['password']}@"
    else:
        auth = ""
    url = f"{scheme}://{auth}{parts['host']}:{parts['port']}"
    return {"http": url, "https": url}


def check_protocol(proxy_data: str) -> dict:
    """Verify which protocol the proxy actually speaks (not trust input)."""
    result = {
        "confirmed_protocol": None,
    }

    parts = parse_proxy_parts(proxy_data)
    if parts is None:
        return result

    working = []
    for scheme in PROTOCOLS_TO_TRY:
        proxy_dict = build_proxy_dict(scheme, parts)
        try:
            response = requests.get(
                LATENCY_URL,
                proxies=proxy_dict,
                timeout=10,
            )
            response.raise_for_status()
            working.append(scheme)
        except Exception:
            continue

    if len(working) == 0:
        print("[identity] protocol check: no scheme worked")
        return result

    claimed = parts["claimed"]
    if claimed in working:
        result["confirmed_protocol"] = claimed
    else:
        result["confirmed_protocol"] = working[0]

    return result
