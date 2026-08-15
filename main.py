import requests
import time
import json
from analyzer import gather
from measure import get_real_ip, check_anonymity, check_speed, check_stability


def load_proxies(filename: str) -> list[str]:
    """Getting proxy ip addresses and ports from txt file"""
    proxies = []
    try:
        with open(filename, "r") as file:
            for line in file:
                new_line = line.strip()
                if new_line != "":
                    proxies.append(new_line)
    except FileNotFoundError:
        print(f"Error {filename} file  not found ! ")
    except Exception as e:
        print(f"Error {e}")
    return proxies


def parse_proxy(proxy_data: str) -> dict | None:
    """Proxy is sorted and formatted"""
    if not proxy_data:
        return None

    if proxy_data.startswith("socks5://"):
        protocol = "socks5"
        proxy_data = proxy_data.replace("socks5://", "")
    elif proxy_data.startswith("http://"):
        protocol = "http"
        proxy_data = proxy_data.replace("http://", "")
    elif proxy_data.startswith("https://"):
        protocol = "https"
        proxy_data = proxy_data.replace("https://", "")

    else:
        protocol = "http"

    # format: user:pass@host:port
    if "@" in proxy_data:
        credentials, address = proxy_data.split("@")
        user_name, password = credentials.split(":")
        host, port = address.split(":")
        url = f"{protocol}://{user_name}:{password}@{host}:{port}"
        return {"http": url, "https": url}

    data_parts = proxy_data.split(":")

    if len(data_parts) == 2:
        host = data_parts[0]
        port = data_parts[1]
        url = f"{protocol}://{host}:{port}"
        return {"http": url, "https": url}

    elif len(data_parts) == 4:
        host = data_parts[0]
        port = data_parts[1]
        user_name = data_parts[2]
        password = data_parts[3]
        url = f"{protocol}://{user_name}:{password}@{host}:{port}"
        return {"http": url, "https": url}

    return None


def mask_proxy(proxy_data: str) -> str:
    """
    Hide username/password in output.
    Keep only protocol + host + port, e.g.:
      socks5://user:pass@1.2.3.4:1080  →  socks5://1.2.3.4:1080
      host:port:user:pass              →  host:port
    """
    if not proxy_data:
        return proxy_data

    protocol = ""
    rest = proxy_data
    for prefix in ("socks5://", "https://", "http://"):
        if rest.startswith(prefix):
            protocol = prefix
            rest = rest[len(prefix) :]
            break

    # format: user:pass@host:port
    if "@" in rest:
        rest = rest.split("@", 1)[1]
        return f"{protocol}{rest}"

    # format: host:port:user:pass
    parts = rest.split(":")
    if len(parts) >= 4:
        rest = f"{parts[0]}:{parts[1]}"

    return f"{protocol}{rest}"


def check_proxy(proxy_data: str) -> dict:
    """Proxy data are tested to get exit ip"""
    test_result = {
        "proxy": proxy_data,
        "status": "dead",
        "latency_ms": None,
        "exit_ip": None,
    }

    proxy_dict = parse_proxy(proxy_data)
    if proxy_dict is None:
        return test_result

    test_result["proxy_dict"] = proxy_dict

    try:
        start_time = time.time()
        response = requests.get(
            "https://api.ipify.org?format=json", proxies=proxy_dict, timeout=10
        )
        latency_ms = round((time.time() - start_time) * 1000)
        exit_ip = response.json()["ip"]

        test_result["status"] = "alive"
        test_result["latency_ms"] = latency_ms
        test_result["exit_ip"] = exit_ip
    except Exception:
        return test_result

    return test_result


def main():

    real_ip = get_real_ip()
    # The real ip checks before the proxy checks.
    if real_ip is None:
        print("Warning: no baseline IP, anonymity checks will be skipped")
    else:
        print(f"Real IP (baseline, no proxy): {real_ip}\n")

    proxies = load_proxies("proxies.txt")

    all_test_results = []
    for proxy in proxies:
        print(f"Checking: {proxy}")
        result = check_proxy(proxy)

        if result["status"] == "alive" and result["exit_ip"]:
            summary = gather(result["exit_ip"])
            result.update(summary)

            if real_ip is not None:
                anon = check_anonymity(result["proxy_dict"], real_ip)
                result.update(anon)
            else:
                result["anonymity_level"] = None
                result["leaked_headers"] = []

            # download speed through the proxy (Mbps, not latency)
            speed = check_speed(result["proxy_dict"])
            result.update(speed)

            # stability: latency several times → min / median / max + stable
            stability = check_stability(result["proxy_dict"])
            result.update(stability)

        all_test_results.append(result)
        print(
            f"->{result.get('status')} | {result.get('latency_ms')} ms | "
            f"{result.get('exit_ip')} | anon={result.get('anonymity_level')} | "
            f"{result.get('download_mbps')} Mbps | "
            f"stable={result.get('stable')} "
            f"(min={result.get('latency_min')} "
            f"med={result.get('latency_median')} "
            f"max={result.get('latency_max')})\n"
        )

    # Clean output: no credentials / no internal proxy_dict in results.json
    for r in all_test_results:
        r.pop("proxy_dict", None)
        if "proxy" in r:
            r["proxy"] = mask_proxy(r["proxy"])

    with open("results.json", "w", encoding="utf-8") as file:
        json.dump(all_test_results, file, indent=2, ensure_ascii=False)

    print("\nresults.json is being written in the document")


if __name__ == "__main__":
    main()
