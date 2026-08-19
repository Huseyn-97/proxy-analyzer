"""
Performance: latency (ms) stability + download speed (Mbps).
"""

import time

import requests

DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=102400"
LATENCY_URL = "https://api.ipify.org?format=json"
LATENCY_RUNS = 5
STABLE_MAX_RATIO = 2.0


def check_speed(proxy_dict: dict) -> dict:
    """Download a small file through the proxy and report throughput in Mbps."""
    result = {
        "download_mbps": None,
    }

    if proxy_dict is None:
        return result

    try:
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

        mbps = (size_bytes * 8) / (elapsed * 1_000_000)
        result["download_mbps"] = round(mbps, 3)

    except Exception as e:
        print(f"[performance] speed check failed: {e}")
        return result

    return result


def _median(numbers: list[float]) -> float:
    """Return the middle value of a sorted list."""
    sorted_nums = sorted(numbers)
    mid = len(sorted_nums) // 2
    if len(sorted_nums) % 2 == 1:
        return sorted_nums[mid]
    return (sorted_nums[mid - 1] + sorted_nums[mid]) / 2


def check_stability(proxy_dict: dict) -> dict:
    """Run latency several times → min / median / max + stable flag."""
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
            continue

    if len(samples) < 3:
        print("[performance] stability check: not enough latency samples")
        return result

    latency_min = min(samples)
    latency_max = max(samples)
    latency_median = _median(samples)

    result["latency_min"] = round(latency_min)
    result["latency_median"] = round(latency_median)
    result["latency_max"] = round(latency_max)

    if latency_median > 0 and latency_max <= latency_median * STABLE_MAX_RATIO:
        result["stable"] = True
    else:
        result["stable"] = False

    return result
