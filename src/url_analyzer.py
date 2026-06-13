import re
import quopri  # Built-in library to decode raw email line breaks
from urllib.parse import urlparse
from difflib import SequenceMatcher
import requests


def extract_urls(text):
    """
    Cleans raw email text transformations (Quoted-Printable) 
    and reliably extracts complete URLs without truncation.
    """
    # Fix 1: Decode Quoted-Printable elements common in raw email streams
    # This removes soft line breaks (=\n) and converts hex flags like '=3D' to '='
    if "=\n" in text or "=3D" in text:
        try:
            text = quopri.decodestring(text.encode('utf-8')).decode('utf-8', errors='ignore')
        except Exception:
            # Fallback manual patch if stream encoding is forced raw
            text = text.replace("=\n", "").replace("=3D", "=")

    # Fix 2: Switch to a greedy regex pattern to capture the entire URL string.
    # Lazy matching (+?) can cut off early on encoded strings or spaces.
    raw_urls = re.findall(r"https?://[^\s<>\"']+", text)

    # Strip out any trailing punctuation picked up from regular text sentences
    cleaned_urls = []
    for url in raw_urls:
        cleaned_urls.append(url.rstrip('.,;:?!)]}'))
        
    return list(dict.fromkeys(cleaned_urls))


def analyze_url(url):
    score = 0
    findings = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    full_path = parsed.path.lower()

    suspicious_tlds = [".xyz", ".top", ".click", ".zip", ".gq", ".tk"]
    url_shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
    suspicious_words = ["login", "verify", "secure", "update", "account", "bank"]
    trusted_brands = ["google", "microsoft", "paypal", "amazon", "apple", "facebook", "instagram", "github", "linkedin", "netflix"]

    # Check both the domain and full path for keywords
    if any(word in (domain + full_path) for word in suspicious_words):
        score += 15
        findings.append("⚠️ Credential Harvesting Keywords")

    if any(domain.endswith(tld) for tld in suspicious_tlds):
        score += 25
        findings.append("⚠️ Suspicious TLD")

    if parsed.scheme != "https":
        score += 20
        findings.append("⚠️ Non-HTTPS URL")

    if len(domain) > 30:
        score += 10
        findings.append("⚠️ Unusually Long Domain")

    if any(shortener in domain for shortener in url_shorteners):
        score += 20
        findings.append("⚠️ URL Shortener Detected")

    if domain.count("-") >= 2:
        score += 15
        findings.append("⚠️ Excessive Hyphens")

    if len(domain.split(".")) > 3:
        score += 15
        findings.append("⚠️ Excessive Subdomains")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        score += 30
        findings.append("⚠️ IP Address URL")

    # Fix 3: Robust base-domain extraction that accounts for regional domains (e.g., .co.in, .com.br)
    domain_parts = domain.split(".")
    
    # If using a country-code second-level domain (like amazon.co.in), step back 3 layers
    if len(domain_parts) >= 3 and domain_parts[-2] in ["com", "co", "org", "gov", "edu", "net"]:
        base_domain = domain_parts[-3]
    elif len(domain_parts) >= 2:
        base_domain = domain_parts[-2]
    else:
        base_domain = domain

    # Typosquatting Analysis Logic
    for brand in trusted_brands:
        similarity = SequenceMatcher(None, base_domain, brand).ratio()

        if ((similarity >= 0.80 or brand in base_domain) and base_domain != brand):
            score += 50
            findings.append(
                f"🚨 Possible {brand.title()} Typosquatting (Similarity: {round(similarity*100)}%)"
            )

    return {
        "domain": domain if domain else url,
        "score": score,
        "findings": findings
    }


def get_final_destination(url):
    try:
        # Trace the URL redirect headers safely
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except Exception:
        # If the link fails or times out, safely return the original URL
        return url