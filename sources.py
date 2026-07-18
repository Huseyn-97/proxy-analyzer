from abc import ABC, abstractmethod
import requests
import os
from dotenv import load_dotenv
from bs4 import BeautifulSoup 

load_dotenv()

class Source(ABC):
    """"
    Base class for all IP intelligence sources 
    (proxycheck, IPQS, AbuseIPDB, Scamalytics, etc.).
    Every subclass must implement fetch()!
    """

    name = "base"

    @abstractmethod
    def fetch(self, ip: str) -> dict:
        """"
        Look up the given IP address and return the result as a dict.
        Should raise an exception on failure, never return None.
        """
        raise NotImplementedError
    

class ProxyCheckSource(Source):
    """Looks up an IP using the proxycheck.io free API (guest mode, no key)."""

    name = "proxycheck"

    def fetch(self, ip: str) -> dict:
         """"Returns proxycheck.io's raw JSON response for the given IP address."""
         url = f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1"
         response = requests.get(url, timeout=5)
         response.raise_for_status()
         data = response.json()

         if data.get("status") != "ok":
             raise ValueError(f"proxychceck.io returned status={data.get('status')} for {ip}")
         
         return data 

class IpApiSource(Source):
    """Looks up geo/ASN info for an IP using ip- api.com(free, no key)."""

    name = "ip-api"

    def fetch(self, ip: str) -> dict:
        """"Returns ip-api.com's raw JSON response for the given IP ."""
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "success":
            raise ValueError(f"ip-api returned status={data.get('status')} for {ip}")
        
        return data
    
class IpInfoSource(Source):
    """"Looks up geo/ASN info for an IP using ipinfo.io (free, no key needed for basic lookups)."""

    name = "ipinfo"

    def fetch(self, ip: str) -> dict:
        """"Returns ipinfo.io's raw JSON response for the given IP."""
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        if data.get("bogon"):
            raise ValueError(f"ipinfo returned bogon(no geo data) for {ip}")
        
        return data 
    
class IpWhoIsSource(Source):
    """"Looks up geo/ASN info for an IP using ipwhois.io(free, no key)."""

    name = "ipwhois"

    def fetch(self, ip:str) -> dict:
        """"Returns ipwho.is's raw JSON response for the given IP."""
        url = f"https://ipwho.is/{ip}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        if not data.get("success", True):
            raise ValueError(f"ipwho.is returned success=False ({data.get('message')}) for {ip}")
        
        return data

class AbuseIPDBSource(Source):
    """Looks up an IP's abuse reputation using the AbuseIPDB API (requires API key)."""

    name = "abuseipdb"

    def fetch(self, ip: str) -> dict:
        """Returns AbuseIPDB's raw JSON response for the given IP."""
        api_key = os.getenv("ABUSEIPDB_KEY")
        if not api_key:
            raise ValueError("ABUSEIPDB_KEY not found in environment (.env)")

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
        }
        response = requests.get(url, headers=headers, params=params, timeout=5)
        response.raise_for_status()
        data = response.json()

        if not data.get("data", {}).get("isPublic", True):
            raise ValueError(f"AbuseIPDB: {ip} is not a public IP")
        
        return data 
    
class IPQualityScoreSource(Source):
    """Looks up an IP's fraud score and flags using the IPQualityScore API (requires API key)."""

    name = "ipqs"

    def fetch(self, ip: str) -> dict:
        """Returns IPQualityScore's raw JSON response for the given IP."""
        api_key = os.getenv("IPQS_KEY")
        if not api_key:
            raise ValueError("IPQS_KEY not found in environment (.env)")

        url = f"https://www.ipqualityscore.com/api/json/ip/{api_key}/{ip}"
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()

        if not data.get("success", True):
            raise ValueError(f"IPQS returned success=false ({data.get('message')}) for {ip}")
        
        if data.get("ISP") == "Private IP Address":
            raise ValueError(f"IPQS: {ip} is a private IP (no fraud data)")

        return data
    
class ScamalyticsSource(Source):
    """Looks up an IP's fraud score by parsing the Scamalytics HTML page (no API key)."""

    name = "scamalytics"

    def fetch(self, ip: str) -> dict:
        """Parses Scamalytics' HTML page and returns the fraud score for the given IP."""
        url = f"https://scamalytics.com/ip/{ip}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        score_div = soup.find("div", class_="score")

        if score_div is None:
            raise ValueError(f"Scamalytics: could not find score element for {ip}")

        text = score_div.get_text(strip=True)
        score = int(text.replace("Fraud Score:", "").strip())

        return {"ip": ip, "scamalytics_score": score, "raw_text": text}
    
class GreyNoiseSource(Source):
    """Looks up an IP's threat activity using the GreyNoise Community API (requires API key)."""

    name = "greynoise"

    def fetch(self, ip: str) -> dict:
        """Returns GreyNoise Community API's raw JSON response for the given IP."""
        api_key = os.getenv("GREYNOISE_KEY")
        if not api_key:
            raise ValueError("GREYNOISE_KEY not found in environment (.env)")

        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {
            "key": api_key,
            "Accept": "application/json",
        }
        response = requests.get(url, headers=headers, timeout=5)

        if response.status_code == 404:
            return {"ip": ip, "noise": False, "riot": False, "classification": "unknown", "message": "IP not observed by GreyNoise"}
        
        if response.status_code == 400:
           raise ValueError(f"GreyNoise: {ip} is not a valid public IP")
        
        response.raise_for_status()
        return response.json()
    

    
    



    
