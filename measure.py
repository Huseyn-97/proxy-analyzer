import time

import requests

# Headers that often carry the client's real IP (leak = transparent)
LEAK_HEADERS = ("X-Forwarded-For", "Forwarded", "X-Real-IP")

# Header that reveals "a proxy was used" (without necessarily leaking IP)
PROXY_REVEAL_HEADERS = ("Via",)

# Small file (~100 KB) so we don't burn proxy bandwidth
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=102400"

# Stability: repeat a light latency check through the proxy
LATENCY_URL = "https://api.ipify.org?format=json"
LATENCY_RUNS = 5
# Slowest run must not be worse than this many times the median
STABLE_MAX_RATIO = 2.0

# Protocols we actually try (not trust from the input string)
PROTOCOLS_TO_TRY = ("socks5", "http", "https")

# Input prefixes → protocol name.
# Order matters: "https://" must be checked before "http://".
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
            if ip:  # Skip to the next source if empty/None
                return ip
        except Exception:
            continue
    print("[measure] could not get real IP from any service")
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
            proxies=proxy_dict,  # proxy testing
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        headers = data.get("headers", {})
    except Exception as e:
        print(f"[measure] anonymity check failed: {e}")
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


def check_speed(proxy_dict: dict) -> dict:
    """Download a small file through the proxy and report throughput in Mbps."""
    result = {
        "download_mbps": None,
    }

    if proxy_dict is None:
        return result

    try:
        # Start timer, download THROUGH the proxy
        start = time.time()
        response = requests.get(
            DOWNLOAD_URL,
            proxies=proxy_dict,
            timeout=30,
        )
        response.raise_for_status()
        elapsed = time.time() - start

        size_bytes = len(response.content)

        if elapsed <= 0 or size_bytes == 0:
            return result

        # Convert to megabits per second
        mbps = (size_bytes * 8) / (elapsed * 1_000_000)
        result["download_mbps"] = round(mbps, 3)

    except Exception as e:
        print(f"[measure] speed check failed: {e}")
        return result

    return result


def _median(numbers: list[float]) -> float:
    """Return the middle value of a sorted list (beginner-friendly)."""
    sorted_nums = sorted(numbers)
    mid = len(sorted_nums) // 2
    if len(sorted_nums) % 2 == 1:
        return sorted_nums[mid]
    # even count: average of the two middle values
    return (sorted_nums[mid - 1] + sorted_nums[mid]) / 2


def check_stability(proxy_dict: dict) -> dict:
    """
    Run the latency check several times through the proxy.

    Reports min / median / max (ms) and a simple stable flag.
    One good answer + wild later answers = not a good proxy.
    """
    result = {
        "latency_min": None,
        "latency_median": None,
        "latency_max": None,
        "stable": None,
    }

    if proxy_dict is None:
        return result

    samples = []
    for _ in range(LATENCY_RUNS):
        try:
            start = time.time()
            response = requests.get(
                LATENCY_URL,
                proxies=proxy_dict,
                timeout=10,
            )
            response.raise_for_status()
            elapsed_ms = (time.time() - start) * 1000
            samples.append(elapsed_ms)
        except Exception:
            # One failed run: skip it, keep going
            continue

    # Need at least 3 successful runs to judge stability
    if len(samples) < 3:
        print("[measure] stability check: not enough latency samples")
        return result

    latency_min = min(samples)
    latency_max = max(samples)
    latency_median = _median(samples)

    result["latency_min"] = round(latency_min)
    result["latency_median"] = round(latency_median)
    result["latency_max"] = round(latency_max)

    # stable = slowest is not more than 2x the median
    if latency_median > 0 and latency_max <= latency_median * STABLE_MAX_RATIO:
        result["stable"] = True
    else:
        result["stable"] = False

    return result


def _parse_proxy_parts(proxy_data: str) -> dict | None:
    """
    Split a proxy string into pieces we need for protocol tests.

    Supports:
      socks5://user:pass@host:port
      http://host:port
      host:port:user:pass
    """
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


def _build_proxy_dict(scheme: str, parts: dict) -> dict:
    """Build requests proxies= dict for one scheme (socks5 / http / https)."""
    if parts["user"] and parts["password"]:
        auth = f"{parts['user']}:{parts['password']}@"
    else:
        auth = ""
    url = f"{scheme}://{auth}{parts['host']}:{parts['port']}"
    return {"http": url, "https": url}


def check_protocol(proxy_data: str) -> dict:
    """
    Verify which protocol the proxy actually speaks.

    We do NOT copy socks5/http/https from the input string.
    We try each scheme with a real request through the proxy.
    """
    result = {
        "confirmed_protocol": None,
    }

    parts = _parse_proxy_parts(proxy_data)
    if parts is None:
        return result

    working = []
    for scheme in PROTOCOLS_TO_TRY:
        proxy_dict = _build_proxy_dict(scheme, parts)
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
        print("[measure] protocol check: no scheme worked")
        return result

    # Prefer the claimed scheme if it really works; otherwise first that worked
    claimed = parts["claimed"]
    if claimed in working:
        result["confirmed_protocol"] = claimed
    else:
        result["confirmed_protocol"] = working[0]

    return result
