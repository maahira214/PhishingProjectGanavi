"""Shared URL feature extraction (used by BOTH training and prediction)."""
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "account", "signin",
                    "banking", "confirm", "password", "wallet", "suspend"]
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
              "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"}
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "zip", "work"}
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}

# Order matters: this is the model's input vector.
FEATURE_NAMES = ["url_length", "num_dots", "num_hyphens", "num_special_chars",
                 "has_ip", "has_https", "num_subdomains", "suspicious_words",
                 "is_shortener", "has_at_symbol", "unusual_port", "suspicious_pattern"]

# Plain-English labels shown to the user.
FEATURE_LABELS = {
    "url_length": "Very long URL", "num_dots": "Many dots in the URL",
    "num_hyphens": "Many hyphens", "num_special_chars": "Many special characters",
    "has_ip": "IP address used instead of a domain name",
    "has_https": "Connection is not HTTPS", "num_subdomains": "Many subdomains",
    "suspicious_words": "Suspicious words (login, verify, secure...)",
    "is_shortener": "URL shortener hides the real destination",
    "has_at_symbol": "Contains an @ symbol", "unusual_port": "Unusual port number",
    "suspicious_pattern": "Suspicious URL pattern"}


def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def extract_features(url: str) -> dict:
    """Analyse the URL *text only*. The site is never visited."""
    url = normalize_url(url)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    lower = url.lower()
    is_ip = bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host)) or \
        bool(re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host))

    parts = host.split(".")
    base = 3 if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in SECOND_LEVEL else 2
    subdomains = 0 if is_ip else max(0, len(parts) - base)

    pattern = 0
    pattern += "//" in (p.path or "")                      # redirect-style double slash
    pattern += "%" in url                                  # encoded characters
    pattern += host.startswith("xn--") or ".xn--" in host  # punycode look-alikes
    pattern += parts[-1] in RISKY_TLDS if parts else 0     # cheap/abused TLD
    pattern += bool(re.search(r"\d{5,}", host))            # long digit runs in host
    pattern += bool(re.search(r"\.(com|net|org|gov)\.", host))  # "paypal.com.evil.xyz"

    try:
        port = p.port
    except ValueError:
        port = -1
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_special_chars": len(re.findall(r"[^A-Za-z0-9.\-/:]", url)),
        "has_ip": int(is_ip),
        "has_https": int(p.scheme == "https"),
        "num_subdomains": subdomains,
        "suspicious_words": sum(w in lower for w in SUSPICIOUS_WORDS),
        "is_shortener": int(host in SHORTENERS),
        "has_at_symbol": int("@" in url),
        "unusual_port": int(port not in (None, 80, 443)),
        "suspicious_pattern": int(pattern),
    }


def to_vector(features: dict) -> list:
    return [features[n] for n in FEATURE_NAMES]
