"""
UDP capability check (next step).

HTTP → n/a (http)
SOCKS5 → UDP ASSOCIATE (to implement)
"""


def check_udp(proxy_data: str, protocol: str | None) -> dict:
    """Placeholder until the UDP step is implemented."""
    result = {
        "udp_supported": None,
    }

    if protocol is None:
        return result

    if protocol in ("http", "https"):
        result["udp_supported"] = "n/a (http)"
        return result

    # SOCKS5 real test comes next
    result["udp_supported"] = None
    return result
