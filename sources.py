from abc import ABC, abstractmethod
import requests

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
         return response.json()

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
    
    



    
