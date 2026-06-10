import re
import math
import whois
import requests
from urllib.parse import urlparse
from collections import Counter
from datetime import datetime
import tldextract

# ── Whitelist of known legitimate domains ─────────────────────────────────
WHITELIST = [
    'google.com', 'wikipedia.org', 'github.com', 'youtube.com',
    'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'amazon.com', 'microsoft.com', 'apple.com', 'reddit.com',
    'netflix.com', 'spotify.com', 'whatsapp.com', 'telegram.org',
    'stackoverflow.com', 'medium.com', 'notion.so', 'figma.com',
]

def is_whitelisted(url: str) -> bool:
    # Ensure scheme is present for tldextract to parse the domain correctly
    normalized_url = url
    if "://" not in url:
        normalized_url = f"http://{url}"
    ext = tldextract.extract(normalized_url)
    domain = f"{ext.domain}.{ext.suffix}"
    return domain in WHITELIST


# ── Core 12 features for the ML model ────────────────────────────────────
def extract_features(url: str) -> list:
    # Normalize URL by ensuring a scheme is present so urlparse extracts netloc/path correctly
    normalized_url = url
    if "://" not in url:
        normalized_url = f"http://{url}"
        
    parsed = urlparse(normalized_url)
    ext = tldextract.extract(normalized_url)

    features = [
        len(url),                                                                # url_length
        1 if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc) else 0,           # has_ip
        1 if '@' in url else 0,                                                 # has_at_symbol
        1 if '//' in url[7:] else 0,                                            # has_double_slash
        len(ext.subdomain.split('.')) if ext.subdomain and ext.subdomain != 'www' else 0,  # subdomain_count
        1 if parsed.scheme == 'https' else 0,                                   # has_https
        len(ext.domain),                                                         # domain_length
        len(parsed.path),                                                        # path_length
        1 if '-' in ext.domain else 0,                                          # hyphen_in_domain
        sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0,        # digit_ratio
        sum(url.count(c) for c in ['%', '=', '?', '&']),                       # special_char_count
        1 if any(t in parsed.path for t in ['.com', '.net', '.org']) else 0,   # tld_in_path
    ]
    return features


# ── URL Entropy ───────────────────────────────────────────────────────────
def calc_entropy(url: str) -> float:
    counts = Counter(url)
    length = len(url)
    if length == 0:
        return 0.0
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 2)


# ── Domain Age via WHOIS ──────────────────────────────────────────────────
def get_domain_age(domain: str) -> str:
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            if age_days < 30:
                return f"{age_days} Days (New)"
            elif age_days < 365:
                return f"{age_days // 30} Months"
            else:
                return f"{age_days // 365} Years"
    except Exception:
        pass
    return "Unknown"


# ── WHOIS Privacy check ───────────────────────────────────────────────────
def get_whois_privacy(domain: str) -> str:
    try:
        w = whois.whois(domain)
        org = str(w.org or '') + str(w.emails or '')
        if any(word in org.lower() for word in ['redacted', 'privacy', 'private', 'protect']):
            return "Redacted/Private"
        return "Public"
    except Exception:
        return "Unknown"


# ── Redirect Count ────────────────────────────────────────────────────────
def get_redirect_count(url: str) -> str:
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        count = len(response.history)
        if count == 0:
            return "0 (Normal)"
        elif count <= 2:
            return f"{count} (Normal)"
        else:
            return f"{count} (Abnormal)"
    except Exception:
        return "Unknown"


# ── Server Country via ipinfo.io ──────────────────────────────────────────
def get_server_country(domain: str) -> str:
    try:
        response = requests.get(f"https://ipinfo.io/{domain}/json", timeout=5)
        data = response.json()
        city = data.get('city', '')
        country = data.get('country', '')
        if city and country:
            return f"{city}, {country}"
        return country or "Unknown"
    except Exception:
        return "Unknown"


# ── Full info for UI display ──────────────────────────────────────────────
def extract_full_info(url: str) -> dict:
    normalized_url = url
    if "://" not in url:
        normalized_url = f"http://{url}"
    parsed = urlparse(normalized_url)
    ext = tldextract.extract(normalized_url)
    domain = f"{ext.domain}.{ext.suffix}"

    features = extract_features(url)

    info = {
        "url_length":         f"{features[0]} chars {'(Extreme)' if features[0] > 100 else '(Normal)'}",
        "has_ip":             "True" if features[1] else "False",
        "has_at_symbol":      "Present" if features[2] else "Not Present",
        "has_double_slash":   "Detected" if features[3] else "Not Detected",
        "subdomains":         f"{features[4]} Detected" if features[4] > 0 else "None",
        "https_protocol":     "Valid (SSL/TLS)" if features[5] else "Not Secure (HTTP)",
        "domain_length":      str(features[6]),
        "path_length":        str(features[7]),
        "hyphen_in_domain":   "Detected" if features[8] else "Not Detected",
        "digit_ratio":        f"{features[9]:.2f}",
        "special_char_count": f"{features[10]} {'(Suspicious)' if features[10] > 5 else '(Normal)'}",
        "tld_in_path":        "Detected" if features[11] else "Not Detected",
        "url_entropy":        calc_entropy(url),
        "domain_age":         get_domain_age(domain),
        "whois_data":         get_whois_privacy(domain),
        "redirect_count":     get_redirect_count(url),
        "server_origin":      get_server_country(ext.domain),
    }

    return info