"""Rule-based risk engine + optional hybrid with ML.

Weights and thresholds are PROJECT ASSUMPTIONS. In a real system, calibrate them on validation data.
No single indicator proves phishing - the score is a risk estimate that supports analyst judgment.
"""
from .attachment_analyzer import analyze_attachment
from .content_analyzer import analyze_email_content
from .features import extract_email_features
from .sender_analyzer import analyze_sender
from .url_analyzer import analyze_url, extract_urls

WEIGHTS = {
    "suspicious_sender": 15, "urgency": 10, "credential_request": 20, "suspicious_url": 20,
    "suspicious_attachment": 25, "generic_greeting": 5, "fear_language": 10,
    "financial_pressure": 10, "reward_claim": 10, "personal_info_request": 10,
}
RULE_WEIGHT, ML_WEIGHT = 0.6, 0.4

RECOMMENDATIONS = {
    "HIGH RISK / LIKELY PHISHING": [
        "Do not click links or open attachments.",
        "Verify the sender through a trusted channel (not by replying).",
        "Report the email to your security team.",
        "Use the organisation's official website/app directly."],
    "SUSPICIOUS": [
        "Treat links and attachments with caution.",
        "Check the sender address and domain spelling carefully.",
        "Confirm the request through a trusted channel before acting."],
    "MODERATE RISK": ["A few warning signs were found - verify the request if it is unexpected."],
    "LOW RISK": ["No strong indicators found, but stay alert: this is not a guarantee of safety."],
}


def classify(score):
    if score <= 20:
        return "LOW RISK"
    if score <= 40:
        return "MODERATE RISK"
    if score <= 70:
        return "SUSPICIOUS"
    return "HIGH RISK / LIKELY PHISHING"


def calculate_phishing_score(flags):
    """flags: set of indicator names that fired -> capped 0-100 score."""
    return min(sum(WEIGHTS[f] for f in flags), 100)


def analyze_email(sender, subject, body, attachment_name="", display_name=None,
                  expected_domain=None, use_ml=False):
    sender_r = analyze_sender(sender, display_name, expected_domain)
    content = analyze_email_content(subject, body)
    urls = [analyze_url(u) for u in extract_urls(body)]
    att = analyze_attachment(attachment_name)
    counts = content["counts"]

    fired = {}  # indicator -> explanation
    if sender_r["suspicious"]:
        fired["suspicious_sender"] = "; ".join(sender_r["findings"])
    for key, cat in [("urgency", "urgency"), ("credential_request", "credential"),
                     ("fear_language", "fear"), ("financial_pressure", "financial"),
                     ("reward_claim", "reward"), ("personal_info_request", "personal_info")]:
        if counts[cat]:
            hits = next(f["matches"] for f in content["findings"] if f["category"] == cat)
            fired[key] = "Matched: " + ", ".join(hits)
    if any(u["suspicious"] for u in urls):
        fired["suspicious_url"] = "; ".join(f for u in urls if u["suspicious"] for f in u["findings"])
    if att["suspicious"]:
        fired["suspicious_attachment"] = "; ".join(att["findings"])
    if content["generic_greeting"]:
        fired["generic_greeting"] = "Generic greeting instead of your name"

    rule_score = calculate_phishing_score(fired)
    ml_prob, final = None, rule_score
    if use_ml:
        try:
            from ml.predict import predict_proba
            ml_prob = predict_proba(sender, subject, body, attachment_name)
        except Exception:
            ml_prob = None
        if ml_prob is not None:
            final = round(RULE_WEIGHT * rule_score + ML_WEIGHT * ml_prob * 100)
    classification = classify(final)
    reasons = [{"indicator": k, "points": WEIGHTS[k], "detail": v} for k, v in fired.items()]
    return {
        "score": final, "rule_score": rule_score, "ml_probability": ml_prob,
        "classification": classification, "reasons": reasons,
        "sender": sender_r, "content": content, "urls": urls, "attachment": att,
        "recommendations": RECOMMENDATIONS[classification],
        "features": extract_email_features(sender, subject, body, attachment_name),
    }
