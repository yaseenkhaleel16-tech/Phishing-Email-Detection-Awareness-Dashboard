"""Content analyzer: finds social-engineering language in the subject + body.

It only reads text. Nothing is opened, clicked or executed.
"""
import re

CATEGORIES = {
    "urgency": ["urgent", "immediately", "act now", "right away", "asap",
                "within 24 hours", "today only", "final notice", "expires today", "last chance"],
    "fear": ["will be suspended", "account suspended", "account will be closed", "will be locked",
             "unauthorized activity", "suspicious activity", "legal action",
             "permanently disabled", "security breach", "will be terminated"],
    "financial": ["outstanding payment", "invoice due", "payment overdue", "wire transfer",
                  "gift card", "unpaid invoice", "payment failed", "overdue balance"],
    "credential": ["verify your password", "confirm your password", "enter your password",
                   "login credentials", "verify your account", "verify your identity",
                   "reset your password", "update your password", "your username and password"],
    "reward": ["you have won", "you've won", "claim your prize", "congratulations",
               "free gift", "lottery winner"],
    "personal_info": ["confirm your personal details", "social security", "date of birth",
                      "bank details", "card number", "confirm your identity"],
}

EXPLANATIONS = {
    "urgency": "Time pressure pushes people to act before thinking.",
    "fear": "Threats (suspension, legal action) are used to trigger panic.",
    "financial": "Payment pressure is common in fake invoice / fraud emails.",
    "credential": "Legitimate organisations rarely ask you to verify passwords by email.",
    "reward": "Unexpected prizes are a classic lure.",
    "personal_info": "Requests for personal data can be used for identity theft.",
}

GENERIC_GREETING = re.compile(
    r"^\s*(dear\s+(customer|user|member|client|valued\s+\w+|account\s+holder|sir|madam)|hello\s+user|greetings)\b",
    re.I)


def analyze_email_content(subject, body):
    subject, body = subject or "", body or ""
    text = f"{subject}\n{body}".lower()
    findings, counts = [], {}
    for cat, phrases in CATEGORIES.items():
        hits = [p for p in phrases if p in text]
        counts[cat] = len(hits)
        if hits:
            findings.append({"category": cat, "matches": hits, "explanation": EXPLANATIONS[cat]})
    letters = [c for c in subject + body if c.isalpha()]
    upper_ratio = sum(c.isupper() for c in letters) / len(letters) if letters else 0.0
    return {
        "findings": findings,
        "counts": counts,
        "generic_greeting": bool(GENERIC_GREETING.search(body[:80])),
        "uppercase_ratio": round(upper_ratio, 3),
        "exclamation_count": text.count("!"),
    }
