import json
import os
import time

from sources import (
    ProxyCheckSource,
    IpApiSource,
    IpInfoSource,
    IpWhoIsSource,
    AbuseIPDBSource,
    IPQualityScoreSource,
    ScamalyticsSource,
    GreyNoiseSource,
)

CACHE_FILE = "cache.json"
CACHE_TTL = 86400  # 24 hours in seconds


def load_cache() -> dict:
    """Loads the cache file. Returns empty dict if it doesn't exist."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return {}


def save_cache(cache: dict) -> None:
    """Saves the cache dict back to the cache file."""
    with open(CACHE_FILE, "w", encoding="utf-8") as file:
        json.dump(cache, file, indent=2, ensure_ascii=False)


def extract(gathered: dict) -> dict:
    """Takes the raw gather() result and pulls the useful fields into one clean summary."""
    ip = gathered["ip"]
    sources = gathered["sources"]

    summary = {"ip": ip}

    if "ip-api" in sources:
        ipapi = sources["ip-api"]
        summary["country_ipapi"] = ipapi.get("country")
        summary["city_ipapi"] = ipapi.get("city")
        summary["countrycode_ipapi"] = ipapi.get("countryCode")

    if "ipinfo" in sources:
        ipinfo = sources["ipinfo"]
        summary["country_ipinfo"] = ipinfo.get("country")
        summary["city_ipinfo"] = ipinfo.get("city")
        summary["countrycode_ipinfo"] = ipinfo.get("country")

    if "ipwhois" in sources:
        ipwhois = sources["ipwhois"]
        summary["country_ipwhois"] = ipwhois.get("country")
        summary["city_ipwhois"] = ipwhois.get("city")
        summary["countrycode_ipwhois"] = ipwhois.get("country_code")

    if "proxycheck" in sources:
        pc = sources["proxycheck"]
        pc_data = pc.get(ip, {})
        summary["proxycheck_type"] = pc_data.get("type")
        summary["proxycheck_proxy"] = pc_data.get("proxy")

    if "abuseipdb" in sources:
        abuse_data = sources["abuseipdb"].get("data", {})
        summary["abuse_score"] = abuse_data.get("abuseConfidenceScore")
        summary["abuse_reports"] = abuse_data.get("totalReports")

    if "ipqs" in sources:
        ipqs = sources["ipqs"]
        summary["fraud_score"] = ipqs.get("fraud_score")
        summary["ipqs_proxy"] = ipqs.get("proxy")
        summary["ipqs_vpn"] = ipqs.get("vpn")
        summary["ipqs_tor"] = ipqs.get("tor")
        summary["ipqs_bot"] = ipqs.get("bot_status")

    if "scamalytics" in sources:
        summary["scamalytics_score"] = sources["scamalytics"].get("scamalytics_score")

    if "greynoise" in sources:
        gn = sources["greynoise"]
        summary["greynoise_noise"] = gn.get("noise")
        summary["greynoise_classification"] = gn.get("classification")

    codes = []
    if summary.get("countrycode_ipapi"):
        codes.append(summary["countrycode_ipapi"])
    if summary.get("countrycode_ipinfo"):
        codes.append(summary["countrycode_ipinfo"])
    if summary.get("countrycode_ipwhois"):
        codes.append(summary["countrycode_ipwhois"])

    unique_codes = set(codes)
    summary["geo_agreement"] = len(unique_codes) == 1

    return summary


def gather(ip: str) -> dict:
    """Runs all intelligence sources for a given IP and merges their results."""

    cache = load_cache()

    # if this IP is in the cache and still fresh, return the cached summary
    if ip in cache:
        age = time.time() - cache[ip]["cached_at"]
        if age < CACHE_TTL:
            print(f"[cache] {ip} loaded from cache")
            return cache[ip]["summary"]

    sources = [
        ProxyCheckSource(),
        IpApiSource(),
        IpInfoSource(),
        IpWhoIsSource(),
        AbuseIPDBSource(),
        IPQualityScoreSource(),
        ScamalyticsSource(),
        GreyNoiseSource(),
    ]

    results = {}
    errors = {}

    for source in sources:
        try:
            results[source.name] = source.fetch(ip)
        except Exception as e:
            errors[source.name] = str(e)

    data = {
        "ip": ip,
        "sources": results,
        "errors": errors,
    }

    # compute the clean summary from the raw data
    summary = extract(data)

    # cache both raw data and the clean summary
    cache[ip] = {
        "cached_at": time.time(),
        "data": data,
        "summary": summary,
    }
    save_cache(cache)

    return summary
