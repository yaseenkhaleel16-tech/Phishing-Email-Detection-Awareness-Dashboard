"""Feature engineering: turns one email into a flat dictionary of numbers (used by ML and dashboards)."""
from .attachment_analyzer import analyze_attachment
from .content_analyzer import analyze_email_content
from .sender_analyzer import analyze_sender
from .url_analyzer import analyze_url, extract_urls, SHORTENERS
from urllib.parse import urlparse


def extract_email_features(sender, subject, body, attachment_name=""):
    c = analyze_email_content(subject, body)
    s = analyze_sender(sender)
    urls = extract_urls(body)
    ua = [analyze_url(u) for u in urls]
    att = analyze_attachment(attachment_name)
    return {
        "urgent_keyword_count": c["counts"]["urgency"],
        "credential_keyword_count": c["counts"]["credential"],
        "financial_keyword_count": c["counts"]["financial"],
        "threat_keyword_count": c["counts"]["fear"],
        "url_count": len(urls),
        "suspicious_url_count": sum(u["suspicious"] for u in ua),
        "has_ip_url": int(any(u.get("is_ip") for u in ua)),
        "has_shortened_url_pattern": int(any((urlparse(u).hostname or "") in SHORTENERS for u in urls)),
        "sender_domain_length": len(s["domain"]),
        "subdomain_count": max(len(s["domain"].split(".")) - 2, 0) if s["domain"] else 0,
        "suspicious_attachment": int(att["suspicious"]),
        "generic_greeting": int(c["generic_greeting"]),
        "contains_password_request": int(c["counts"]["credential"] > 0),
        "contains_personal_info_request": int(c["counts"]["personal_info"] > 0),
        "exclamation_count": c["exclamation_count"],
        "uppercase_ratio": c["uppercase_ratio"],
        "body_length": len(body or ""),
        "subject_length": len(subject or ""),
    }
