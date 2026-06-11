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
