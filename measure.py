import requests


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
            if ip:          # Skip to the next source if empty/None
                return ip
        except Exception:
            continue
    print("[measure] could not get real IP from any service")
    return None
