"""Sender analyzer. An unfamiliar domain is NOT automatically malicious - we only score patterns."""
import re
from email.utils import parseaddr

ADDR_RE = re.compile(r"^[^@\s]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})$")
LURE_WORDS = ["account", "secure", "verify", "login", "alert", "support", "check", "update", "billing"]
# Fictional brands used only for demo display-name checks.
BRAND_TERMS = ["examplebank", "examplepay", "exampleshop", "exampleuniversity"]
SUSPICIOUS_THRESHOLD = 20


def analyze_sender(sender, display_name=None, expected_domain=None):
    _, addr = parseaddr(sender or "")
    m = ADDR_RE.match(addr or "")
    if not m:
        return {"score": 40, "domain": "", "suspicious": True,
                "findings": ["Sender address format is invalid or missing"]}
    domain = m.group(1).lower()
    labels = domain.split(".")
    subdomains = max(len(labels) - 2, 0)
    reg_label = labels[-2] if len(labels) >= 2 else domain
    findings, score = [], 0

    def add(pts, msg):
        nonlocal score
        score += pts
        findings.append(msg)

    if subdomains >= 3:
        add(20, f"Excessive subdomains ({subdomains})")
    if len(domain) > 30:
        add(10, f"Unusually long domain ({len(domain)} chars)")
    if re.search(r"[a-z][0-9][a-z]", reg_label):
        add(15, "Digits inside letters (possible lookalike, e.g. 'paypa1')")
    if domain.count("-") >= 2:
        add(10, "Many hyphens in domain")
    if any("-" in l and any(w in l for w in LURE_WORDS) for l in labels):
        add(25, "Hyphenated domain with account/security words")
    if any(l.startswith("xn--") for l in labels):
        add(20, "Punycode domain (possible lookalike characters)")
    dn = re.sub(r"\s+", "", (display_name or "").lower())
    if dn and any(b in dn and b not in domain.replace("-", "") for b in BRAND_TERMS):
        add(20, "Display name claims a brand that does not match the sender domain")
    if expected_domain and domain != expected_domain.lower().strip():
        add(20, f"Domain differs from the expected organisation domain ({expected_domain})")
    score = min(score, 100)
    return {"score": score, "domain": domain, "findings": findings,
            "suspicious": score >= SUSPICIOUS_THRESHOLD}
