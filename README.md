# Proxy Quality Analyzer — Step 1

A tool that checks a list of proxies, finds their exit IP, measures
response latency, and looks up basic info (country, city, ASN, ISP)
for each one.

## What it does

For each proxy in `proxies.txt`:
1. Sends a request through the proxy to find its exit IP and latency.
2. Looks up the exit IP directly (not through the proxy) using ip-api.com
   to get country, city, ASN, and ISP.
3. Marks the proxy as `alive` or `dead`.

Results are saved to `results.csv` and printed as a table in the console.

## How to run

1. Install dependencies:

pip install -r requirements.txt

2. Add proxies to `proxies.txt`, one per line:

host:port
host:port:username:password

3. Run:

python main.py

## Output

`results.csv` with columns: proxy, status, latency_ms, exit_ip, country, city, asn, isp

## Notes

- Each proxy has a 10-second timeout.
- A 1.4-second delay between geo lookups respects ip-api.com's free-tier
  rate limit (45 requests/minute).