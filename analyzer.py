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

def gather(ip: str) -> dict:
    """Runs all intelligence sources for a given IP and merges their results."""
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

    return {
        "ip": ip,
        "sources": results,
        "errors": errors,
    }