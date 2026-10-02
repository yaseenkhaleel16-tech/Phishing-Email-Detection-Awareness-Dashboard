"""URL analyzer: STATIC string analysis only. URLs are never visited.

Important: HTTPS does NOT mean a site is trustworthy - attackers can get certificates too.
"""
import ipaddress
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "rebrand.ly", "cutt.ly", "short.example.net"}
KEYWORDS = ["login", "signin", "verify", "secure", "account", "update",
            "confirm", "password", "suspend", "wallet", "bank"]
SUSPICIOUS_THRESHOLD = 30


def extract_urls(text):
    return URL_RE.findall(text or "")


def defang(url):
    """Make a URL unclickable for safe display, e.g. hxxp://198[.]51[.]100[.]10/x"""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def analyze_url(url):
    url = (url or "").strip()
    result = {"url_safe": defang(url), "score": 0, "findings": [], "suspicious": False}
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        result.update(score=30, findings=["Malformed URL"], suspicious=True)
        return result

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    labels = host.split(".") if host else []
    subdomains = 0 if is_ip else max(len(labels) - 2, 0)
    hits = [k for k in KEYWORDS if k in (host + p.path + p.query).lower()]

    checks = [
        (is_ip, 35, "Raw IP address used instead of a domain name"),
        (p.scheme != "https", 15, "Not HTTPS (note: HTTPS alone does not prove a site is safe)"),
        (host in SHORTENERS, 20, "URL shortener pattern hides the real destination"),
        (bool(hits), 20, "Credential/account-related keywords: " + ", ".join(hits)),
        (subdomains >= 3, 15, f"Excessive subdomains ({subdomains})"),
        ("@" in p.netloc, 25, "'@' in URL can disguise the real host"),
        (len(url) > 75, 10, f"Very long URL ({len(url)} chars)"),
        (host.count("-") >= 2, 10, "Many hyphens in hostname"),
        (any(l.startswith("xn--") for l in labels), 20, "Punycode hostname (possible lookalike characters)"),
    ]
    for cond, pts, msg in checks:
        if cond:
            result["score"] += pts
            result["findings"].append(msg)
    result["score"] = min(result["score"], 100)
    result["suspicious"] = result["score"] >= SUSPICIOUS_THRESHOLD
    result.update(scheme=p.scheme, hostname=host, path=p.path, query=p.query,
                  url_length=len(url), hostname_length=len(host),
                  subdomain_count=subdomains, is_ip=is_ip, uses_https=p.scheme == "https",
                  keywords=hits)
    return result
