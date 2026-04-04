"""
features.py — Malicious URL Feature Extractor
Extracts a rich set of lexical, structural, and domain-based features
for phishing/malware URL detection models.
"""

from urllib.parse import urlparse, parse_qs #breakes URL into domain, path, query
import re # Regex = pattern detection; used for IP detection, hex encoding (%20), repeated chars (aaaaa)
import math
from collections import Counter # used for entropy calculation; normal domain-> low entropy, phishing->random strings->high entropy
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# model learns these words = danger
SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "account", "bank", "update", "confirm",
    "password", "signin", "webscr", "ebayisapi", "billing", "support",
    "paypal", "free", "lucky", "bonus", "click", "promo", "offer",
    "winner", "selected", "urgent", "limited", "suspend", "unusual",
]

# model learns these words = safe
TRUSTED_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".io"}

#used to hide real destination
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "buff.ly",
    "rebrand.ly", "cutt.ly", "is.gd", "bl.ink", "short.io", "rb.gy",
}

# Regex compiled once for performance
RE_IP = re.compile(r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)") #detects 192.168.1.1
RE_PORT = re.compile(r":\d{2,5}") # detects :8080
RE_HEX_ENCODED = re.compile(r"%[0-9a-fA-F]{2}") #detects %20 %3A, used to make URLs difficult to understand
RE_REPEATED_CHARS = re.compile(r"(.)\1{4,}") # detects aaaaaa $$$$$$, often used in spammy links


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# Measures randomness
# Example:
# google.com → low entropy
# xj3k9z2q.com → high entropy
def _shannon_entropy(s: str) -> float: 
    """Compute Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


#used for: subdomain depth, domain analysis
# Example: secure.paypal.login.com
# subdomain → secure.paypal
# registered → login
# tld → .com
def _get_domain_parts(parsed) -> tuple[str, str, str]:
    """Return (subdomain, registered_domain, tld) from a parsed URL."""
    netloc = parsed.netloc.split(":")[0]  # strip port
    parts = netloc.split(".")
    if len(parts) >= 2:
        tld = "." + parts[-1]
        registered = parts[-2]
        subdomain = ".".join(parts[:-2])
    else:
        tld, registered, subdomain = "", netloc, ""
    return subdomain, registered, tld


# ---------------------------------------------------------------------------
# Feature groups
# ---------------------------------------------------------------------------


#Phishing URLs are: longer, more complex
def _length_features(url: str, parsed) -> dict:
    path = parsed.path
    query = parsed.query
    return {
        "url_length":       len(url),
        "domain_length":    len(parsed.netloc),
        "path_length":      len(path),
        "query_length":     len(query),
        "fragment_length":  len(parsed.fragment),
    }


#attackers: add more dots and numbers
def _count_features(url: str, parsed) -> dict:
    path = parsed.path
    query = parsed.query
    domain = parsed.netloc
    return {
        "num_dots":          url.count("."),
        "num_hyphens":       url.count("-"),
        "num_underscores":   url.count("_"),
        "num_slashes":       url.count("/"),
        "num_question_marks":url.count("?"),
        "num_ampersands":    url.count("&"),
        "num_equals":        url.count("="),
        "num_at":            url.count("@"),
        "num_exclamations":  url.count("!"),
        "num_tildes":        url.count("~"),
        "num_commas":        url.count(","),
        "num_plus":          url.count("+"),
        "num_asterisks":     url.count("*"),
        "num_hashes":        url.count("#"),
        "num_percent":       url.count("%"),
        "num_digits":        sum(c.isdigit() for c in url),
        "num_letters":       sum(c.isalpha() for c in url),
        "digit_ratio":       sum(c.isdigit() for c in url) / max(len(url), 1),
        "uppercase_ratio":   sum(c.isupper() for c in url) / max(len(url), 1),
        "num_path_segments": len([s for s in path.split("/") if s]),
        "num_query_params":  len(parse_qs(query)),
        "num_subdomains":    domain.count("."),
        "domain_hyphens":    domain.count("-"),
    }


# has_ip_address = hiding identity (not safe)
# has_https = basic security check  (safe)
# is_url_shorter = hiding destination (not safe)
def _security_features(url: str, parsed) -> dict:
    subdomain, registered, tld = _get_domain_parts(parsed)
    domain = parsed.netloc.split(":")[0]

    has_ip = bool(RE_IP.search(domain))
    has_port = bool(RE_PORT.search(parsed.netloc))
    has_https = parsed.scheme == "https"
    is_shortener = domain in SHORTENER_DOMAINS or any(
        domain.endswith("." + s) for s in SHORTENER_DOMAINS
    )
    is_trusted_tld = tld in TRUSTED_TLDS
    has_hex_encoding = bool(RE_HEX_ENCODED.search(url))
    has_double_slash_path = "//" in parsed.path
    has_at_sign = "@" in parsed.netloc
    has_port_in_url = has_port

    return {
        "has_https":             int(has_https),
        "has_ip_address":        int(has_ip),
        "has_port":              int(has_port_in_url),
        "has_at_sign":           int(has_at_sign),
        "is_url_shortener":      int(is_shortener),
        "is_trusted_tld":        int(is_trusted_tld),
        "has_hex_encoding":      int(has_hex_encoding),
        "has_double_slash_path": int(has_double_slash_path),
        "has_fragment":          int(bool(parsed.fragment)),
        "scheme_is_data":        int(parsed.scheme == "data"),
        "scheme_is_javascript":  int(parsed.scheme == "javascript"),
        "has_subdomain":         int(bool(subdomain)),
        "excessive_subdomains":  int(subdomain.count(".") >= 2) if subdomain else 0,
    }


#counts words like: login, verify
def _content_features(url: str) -> dict:
    url_lower = url.lower()
    suspicious_count = sum(word in url_lower for word in SUSPICIOUS_WORDS)
    has_repeated_chars = bool(RE_REPEATED_CHARS.search(url))

    # Ratio of non-standard characters
    non_alnum = sum(not c.isalnum() for c in url) #too many special characters = suspicious

    return {
        "suspicious_word_count":  suspicious_count,
        "has_suspicious_words":   int(suspicious_count > 0),
        "has_repeated_chars":     int(has_repeated_chars),
        "non_alnum_ratio":        non_alnum / max(len(url), 1),
    }


# entropy - randomness 
# normal domain: low entropy, suspicious domain: high entropy
def _entropy_features(url: str, parsed) -> dict:
    subdomain, registered, _ = _get_domain_parts(parsed)
    return {
        "url_entropy":        round(_shannon_entropy(url), 4),
        "domain_entropy":     round(_shannon_entropy(parsed.netloc), 4),
        "path_entropy":       round(_shannon_entropy(parsed.path), 4),
        "subdomain_entropy":  round(_shannon_entropy(subdomain), 4),
        "registered_domain_entropy": round(_shannon_entropy(registered), 4),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# the function that model uses
def extract_features(url: str) -> dict:
    """
    Extract a comprehensive feature set from a URL for ML-based
    malicious URL classification.

    Parameters
    ----------
    url : str
        The raw URL string to analyse.

    Returns
    -------
    dict
        Flat dictionary mapping feature name → numeric value (int or float).

    Raises
    ------
    ValueError
        If the input is not a non-empty string.
    """

    # safety check
    if not isinstance(url, str) or not url.strip():
        raise ValueError(f"url must be a non-empty string, got: {url!r}")

    # Normalise — preserve original for length calculations
    url = url.strip()
    parsed = urlparse(url) # break URL into parts

# feature.update(...) combines all feature groups into ONE dictionary
#final output:
# {
#   "url_length": 45,
#   "num_dots": 3,
#   "has_ip_address": 1,
#   ...
# }
#  THIS is what model sees

    features: dict = {}
    features.update(_length_features(url, parsed))
    features.update(_count_features(url, parsed))
    features.update(_security_features(url, parsed))
    features.update(_content_features(url))
    features.update(_entropy_features(url, parsed))

    return features


# This function gives all feature names (like url_length, num_dots, etc.)
# We run extract_features() on a sample URL just to get the structure.
# This way we don’t have to write feature names manually.
# It also makes sure the model always gets features in the same order.
def feature_names() -> list[str]: # returns a list of feature names
    """Return the ordered list of feature names produced by extract_features."""
    sample = extract_features("https://example.com/path?q=1") # we need to see what features exist so we run this, it gives the feature names eg. url_length, num_dots,etc
    return list(sample.keys()) # this extracts the feature names


# ---------------------------------------------------------------------------
# Quick smoke-test
# ---------------------------------------------------------------------------

#Run this code ONLY when I run this file directly
# If you run: python features.py, This block runs
# If another file imports this: from features import extract_features, This block does NOT run 
# this exists for testing your code quickly

# Without affecting your main project.
if __name__ == "__main__":
    # These are sample URLs to test your feature extractor
    test_urls = [
        "https://google.com",
        "http://192.168.1.1/login/verify?account=update",
        "http://bit.ly/3xYz",
        "https://secure-paypal-login.verify-account.suspicious.com/webscr?cmd=update",
        "javascript:alert('xss')",
    ]

    # Go through each URL one by one
    for u in test_urls:
        feats = extract_features(u) # Convert URL → features (numbers)
        print(f"\nURL : {u}")
        print(f"  url_length={feats['url_length']}, "
              f"has_https={feats['has_https']}, "
              f"has_ip_address={feats['has_ip_address']}, "
              f"suspicious_word_count={feats['suspicious_word_count']}, "
              f"url_entropy={feats['url_entropy']}, "
              f"is_url_shortener={feats['is_url_shortener']}")

    print(f"\nTotal features: {len(feature_names())}")
    print("Feature names:", feature_names())
