# Proxy Quality Analyzer

A command-line tool that tests proxies and enriches each working proxy's exit IP with intelligence gathered from multiple external services (geolocation, proxy/VPN detection, fraud scoring, abuse reports, and real-time threat activity).

For each proxy, the tool checks whether it is alive, measures latency, finds its exit IP, and then queries several IP intelligence sources to build a single merged report per proxy.

## Features

- Loads proxies from a text file and tests each one (alive/dead, latency, exit IP).
- Enriches each working proxy's exit IP using 8 intelligence sources.
- Merges all source data into one clean summary per proxy.
- Computes a geo-agreement flag by comparing country codes across geolocation sources.
- Caches results per IP (with a 24-hour TTL) so running twice does not re-hit the APIs.
- Handles source failures gracefully — one failing source does not break the run.
- Loads API keys from a `.env` file, never hard-coded in the source.
- Writes the final results to `results.json`.

## Sources

The tool queries 8 sources for each exit IP:

**Geolocation (×3):**
- **ip-api** — country, city, region, ASN, ISP
- **ipinfo.io** — country, city, org, hostname
- **ipwho.is** — country, city, connection/ASN details

**Reputation / threat intelligence (×5):**
- **proxycheck.io** — proxy/VPN detection, IP type, ASN (JSON)
- **AbuseIPDB** — abuse confidence score, total reports (JSON, API key)
- **IPQualityScore** — fraud score, proxy/VPN/Tor/bot flags (JSON, API key)
- **Scamalytics** — fraud score, parsed from an HTML page (no clean JSON)
- **GreyNoise** — real-time scan activity (`noise`), classification (JSON, API key) — my own research pick

The 3 geolocation sources sometimes disagree on the country, so the tool records each one separately and sets a `geo_agreement` flag.

## Setup

1. Clone the repository:
2. Install the dependencies:
3. Create a `.env` file (copy from `.env.example`) and add your API keys:

## Usage

1. Add your proxies to `proxies.txt`, one per line. Supported formats:
http://host:port
http://host:port:username:password
socks5://host:port:username:password

2. Run the analyzer:
python main.py

3. The tool prints each proxy's status as it runs, and writes the full results to `results.json`.

## Architecture

The project is split into three files, each with a single responsibility:

- **`sources.py`** — defines a `Source` base class and one subclass per service. Every source implements the same `fetch(ip)` interface, so adding a new source only means adding a new class.
- **`analyzer.py`** — holds `gather()` (runs all sources for an IP, with per-source error handling and caching) and `extract()` (merges the different source formats into one clean summary and computes the geo-agreement flag).
- **`main.py`** — the entry point: loads proxies, tests each one, and for every working proxy passes its exit IP through `gather()` before writing everything to `results.json`.

The flow for each proxy is:

```
main.py (test proxy → exit IP)
   → analyzer.py: gather(exit IP)
      → sources.py: each Source.fetch(exit IP)
      → analyzer.py: extract() merges + caches
   → main.py: writes results.json
```
## Design decisions

- **One class per source, shared interface.** Every source inherits from `Source` and implements `fetch(ip)`. This keeps the analyzer independent of any specific service — it just loops over a list of sources. Adding a new source means adding one class and nothing else.

- **Sources raise on failure instead of returning None.** Each source either returns valid data or raises a clear exception. The analyzer catches these per-source, so one failing source (rate limit, bad key, private IP) never breaks the run — it's recorded in an `errors` section instead.

- **Caching stores both raw and cleaned data, with a TTL.** The cache keeps the raw source responses *and* the cleaned summary per IP, and returns the cleaned summary on repeat calls. Raw data is kept so the summary can be re-computed later without re-hitting the APIs. A 24-hour TTL means stale data (fraud scores, Tor status, etc. can change over time) is automatically refreshed instead of being served forever.

- **Geo-agreement is based on country codes, not names.** The three geolocation sources report the country differently ("US" vs "United States"), so comparing names would produce false mismatches. Comparing ISO country codes avoids this.

- **JSON output instead of CSV.** Each proxy now has many fields that can vary depending on which sources succeeded. JSON handles this variable structure cleanly, where CSV would need fixed columns.