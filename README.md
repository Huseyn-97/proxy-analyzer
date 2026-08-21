# Proxy Quality Analyzer

A command-line tool that tests proxies, enriches each working proxy's exit IP with intelligence gathered from multiple external services, and then measures how good the proxy itself is as a connection — how anonymous, how fast, how stable, and what it can actually do.

There are two sides to the tool:

- **Intelligence (what the world knows about the exit IP):** geolocation, proxy/VPN detection, fraud scoring, abuse reports, and real-time threat activity. These lookups go out **directly**.
- **Measurement (how good the proxy is):** anonymity level, download speed, latency stability, real protocol, reachable TCP ports, and UDP capability. These are all measured **through the proxy**.

## Features

**Intelligence (per exit IP):**
- Loads proxies from a text file and tests each one (alive/dead, latency, exit IP).
- Enriches each working proxy's exit IP using 8 intelligence sources.
- Merges all source data into one clean summary per proxy.
- Computes a geo-agreement flag by comparing country codes across geolocation sources.
- Caches results per IP (with a 24-hour TTL) so running twice does not re-hit the APIs.
- Handles source failures gracefully — one failing source does not break the run.
- Loads API keys from a `.env` file, never hard-coded in the source.

**Measurement (per proxy, through the proxy):**
- Classifies anonymity as `transparent` / `anonymous` / `elite` by comparing headers against a known real IP.
- Measures download throughput in Mbps, separate from latency.
- Runs latency several times and reports min / median / max plus a `stable` flag.
- Confirms the real protocol (HTTP / HTTPS / SOCKS5) instead of trusting the input.
- Checks TCP port reachability through the proxy against a configurable target list (mail ports included).
- Tests UDP support: `n/a (http)` for HTTP proxies, a real UDP ASSOCIATE probe for SOCKS5.
- Masks proxy credentials in the output so usernames/passwords never land in `results.json`.

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

## Measurements

Everything here is run **through the proxy** (the intelligence lookups above stay direct):

- **Anonymity** — the tool fetches its own real IP directly once (the baseline), then requests a header-echo endpoint through the proxy. If the real IP leaks in a forwarded header (`X-Forwarded-For`, `Forwarded`, `X-Real-IP`) it's `transparent`; if only a `Via` header reveals a proxy, it's `anonymous`; if nothing gives it away, it's `elite`. Leaked headers are recorded.
- **Speed** — downloads a small file through the proxy and reports throughput in Mbps, kept separate from latency so a slow-but-responsive proxy isn't mislabelled.
- **Stability** — repeats the latency check several times and reports min / median / max. A proxy is `stable` only if its slowest run isn't far off its median.
- **Protocol confirmation** — actually tries HTTP / HTTPS / SOCKS5 through the proxy rather than trusting the scheme in the input string.
- **TCP ports** — opens a CONNECT tunnel (raw socket for HTTP, PySocks for SOCKS5) to each `host:port` in the config and reports which succeed. Mail ports (25, 587, 465, 993, 995) are included by default.
- **UDP** — HTTP proxies can't relay UDP, so they report `n/a (http)`. For SOCKS5, the tool performs a real UDP ASSOCIATE handshake and sends a DNS query through the relay.

## Setup

1. Clone the repository:
   ```
   git clone https://github.com/Huseyn-97/proxy-analyzer.git
   cd proxy-analyzer
   ```

2. Install the dependencies (includes PySocks for SOCKS5 support):
   ```
   pip install -r requirements.txt
   ```

3. Create a `.env` file (copy from `.env.example`) and add your API keys:
   ```
   ABUSEIPDB_KEY=your_abuseipdb_key_here
   IPQS_KEY=your_ipqs_key_here
   GREYNOISE_KEY=your_greynoise_key_here
   ```
   These keys are free to obtain from AbuseIPDB, IPQualityScore, and GreyNoise.

4. (Optional) Create a `config.json` to customize the TCP port targets:
   ```json
   {
     "port_targets": ["smtp.gmail.com:587", "imap.gmail.com:993"],
     "port_timeout_sec": 10
   }
   ```
   If absent, the tool falls back to a default list of mail ports.

## Usage

1. Add your proxies to `proxies.txt`, one per line. Supported formats:
   ```
   http://host:port
   http://user:pass@host:port
   host:port:user:pass
   socks5://user:pass@host:port
   ```

2. Run the analyzer:
   ```
   python main.py
   ```

3. The tool prints each proxy's status as it runs, and writes the full results to `results.json`.

## Architecture

The project is split by responsibility, so each file does one job:

- **`sources.py`** — defines a `Source` base class and one subclass per service. Every source implements the same `fetch(ip)` interface, so adding a new source only means adding a new class.
- **`analyzer.py`** — holds `gather()` (runs all sources for an IP, with per-source error handling and caching) and `extract()` (merges the different source formats into one clean summary and computes the geo-agreement flag).
- **`identity.py`** — proxy parsing plus the anonymity check and protocol confirmation.
- **`performance.py`** — the speed (Mbps) and stability (latency min/median/max) measurements.
- **`ports.py`** — TCP port reachability via CONNECT tunnels, driven by `config.json`.
- **`udp.py`** — the SOCKS5 UDP ASSOCIATE test and DNS probe.
- **`main.py`** — the entry point: loads proxies, tests each one, and for every working proxy runs the intelligence gathering and the measurements before writing everything to `results.json`.

The flow for each proxy is:

```
main.py (test proxy → exit IP)
   → analyzer.py: gather(exit IP)      # intelligence, direct lookups
      → sources.py: each Source.fetch(exit IP)
      → analyzer.py: extract() merges + caches
   → identity / performance / ports / udp   # measurements, through the proxy
   → main.py: mask credentials, write results.json
```

## Design decisions

- **One class per source, shared interface.** Every source inherits from `Source` and implements `fetch(ip)`. This keeps the analyzer independent of any specific service — it just loops over a list of sources. Adding a new source means adding one class and nothing else.

- **Sources raise on failure instead of returning None.** Each source either returns valid data or raises a clear exception. The analyzer catches these per-source, so one failing source (rate limit, bad key, private IP) never breaks the run — it's recorded in an `errors` section instead.

- **Caching stores both raw and cleaned data, with a TTL.** The cache keeps the raw source responses *and* the cleaned summary per IP, and returns the cleaned summary on repeat calls. Raw data is kept so the summary can be re-computed later without re-hitting the APIs. A 24-hour TTL means stale data (fraud scores, Tor status, etc. can change over time) is automatically refreshed instead of being served forever.

- **Geo-agreement is based on country codes, not names.** The three geolocation sources report the country differently ("US" vs "United States"), so comparing names would produce false mismatches. Comparing ISO country codes avoids this.

- **JSON output instead of CSV.** Each proxy has many fields that can vary depending on which sources succeeded and which measurements ran. JSON handles this variable structure cleanly, where CSV would need fixed columns.

- **Measurement is split into focused modules.** Rather than one large measurement file, the work is grouped by concern: `identity` (who the proxy claims to be — anonymity, protocol), `performance` (speed, stability), `ports` (TCP reachability), and `udp`. Each can be understood, tested, and extended on its own.

- **The real IP baseline is fetched from several services with fallback.** Anonymity classification is meaningless without a known real IP, so it's fetched once at startup. Because that single lookup would otherwise be a single point of failure, the tool tries several IP services in turn and uses the first that answers.

- **Two worlds kept strictly separate.** Intelligence lookups go out directly (they describe the exit IP); every measurement goes through the proxy (it describes the proxy). Mixing them would give meaningless results.

- **Protocol is verified, not trusted.** The scheme in the input string is only a claim. The tool actually tries each protocol through the proxy and reports what really works, preferring the claimed one if it does.

- **UDP is only attempted on SOCKS5.** HTTP proxies cannot relay UDP, so they're reported as `n/a (http)` rather than pretending to run a test. SOCKS5 gets a real UDP ASSOCIATE handshake.

- **Credentials never reach the output.** Proxy usernames and passwords are stripped from the `proxy` field (and the internal proxy dict is dropped) before anything is written to `results.json`.

- **Config-driven port targets.** The TCP port list comes from `config.json`, so the same tool can test arbitrary server ports, not just the built-in mail ports, without touching the code.

- **Dead proxies are skipped safely.** Every measurement guards against a missing proxy and wraps its network calls, so a list full of dead proxies runs clean without crashing.