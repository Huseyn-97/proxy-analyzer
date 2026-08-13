import requests

# Headers that often carry the client's real IP (leak = transparent)
LEAK_HEADERS = ("X-Forwarded-For", "Forwarded", "X-Real-IP")

# Header that reveals "a proxy was used" (without necessarily leaking IP)
PROXY_REVEAL_HEADERS = ("Via",)


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
