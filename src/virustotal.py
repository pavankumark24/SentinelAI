import requests
import os
from dotenv import load_dotenv
from urllib.parse import urlparse

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")


def check_url_virustotal(url):
    """
    Extracts the base domain from a URL and queries VirusTotal's 
    Domain Report API for historical threat intelligence data.
    """
    # Defensive check for API key
    if not API_KEY:
        print("[!] VT_API_KEY is missing from environment variables.")
        return None

    try:
        # 1. Extract the base domain safely
        parsed_url = urlparse(url)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
        
        # Remove port numbers if present (e.g., localhost:8501)
        if ":" in domain:
            domain = domain.split(":")[0]
            
        # If the extracted domain is junk or incomplete, return safely
        if not domain or "." not in domain:
            print(f"[!] Invalid domain extracted from URL: {url}")
            return None

        # 2. Setup Headers and query the Domain endpoint
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        
        domain_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        
        response = requests.get(domain_url, headers=headers, timeout=10)
        
        print(f"VT Status Code: {response.status_code}")
        
        if response.status_code != 200:
            print(f"[!] VirusTotal API returned error: {response.text}")
            return None

        data = response.json()
        
        # 3. Pull the live historical engine analysis stats
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})

        if not stats:
            return None

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0)
        }

    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        print("[!] Network connection to VirusTotal failed or timed out.")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred in virustotal module: {e}")
        return None