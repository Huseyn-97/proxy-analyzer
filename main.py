import requests
import csv
import time
from tabulate import tabulate

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

def parse_proxy(proxy_data: str) -> dict|None:
    """Proxy is sorted and formatted"""
    if not proxy_data:
        return None
    
    data_parts = proxy_data.split(":")

    if len(data_parts) == 2:
        host = data_parts[0]
        port = data_parts[1]
        url = f"http://{host}:{port}"
        return {"http": url, "https": url}
    
    elif len(data_parts) == 4:
        host = data_parts[0]
        port = data_parts[1]
        user_name = data_parts[2]
        password = data_parts[3]
        url = f"http://{user_name}:{password}@{host}:{port}"
        return {"http": url, "https": url}
    
    return None

