"""Generate a SYNTHETIC email dataset (600 rows). Only fictional domains / reserved example IPs."""
import csv
import os
import random

random.seed(42)
NAMES = ["Alex", "Priya", "Sam", "Jordan", "Maria", "Chen", "Fatima", "Liam"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
LEGIT_DOMAINS = ["example.com", "example.org", "example.net"]
PHISH_DOMAINS = ["account-check.invalid.test", "secure-verify.example.net", "mail.support.login.example.com",
                 "examp1e-bank.invalid.test", "payroll-update.example.org", "delivery-notice.invalid.test"]

# (category, sender_local, subject, body) -- {n} {name} {day} are filled randomly
LEGIT = [
    ("university notice", "registrar", "Semester schedule update {n}", "Hello {name}, the timetable for next semester is now posted on the student portal: https://portal.example.org/schedule/{n}. Classes begin on Monday."),
    ("HR update", "hr", "Holiday calendar {n}", "Hi {name}, the holiday calendar for the year is attached to the intranet page https://intranet.example.com/hr/{n}. Let us know if you have questions."),
    ("project update", "pm", "Sprint {n} status", "Hi team, sprint {n} is on track. The demo is on {day}. Notes: https://wiki.example.com/sprint/{n}"),
    ("meeting reminder", "training", "Workshop reminder {n}", "Hi {name}, reminder that our cybersecurity workshop is on {day} at 3 PM in Room {n}. See you there."),
    ("shopping confirmation", "orders", "Your order #{n} is confirmed", "Thanks for shopping with ExampleShop, {name}. Order #{n} will ship in 2 days. Track it at https://www.example.com/orders/{n}"),
    ("newsletter", "news", "Weekly newsletter issue {n}", "This week: campus events, a coding club meetup on {day}, and library hours. Read more: https://www.example.org/news/{n}"),
    ("password-change confirmation", "noreply", "Your password was changed", "Hi {name}, this is a confirmation that your password was changed today. If this was you, no action is needed. Manage settings at https://accounts.example.com/settings"),
    ("bank-style notification", "alerts", "Monthly statement ready", "Hello {name}, your ExampleBank statement for this month is available when you sign in at https://www.example.net/statements. We never ask for your password by email."),
    ("hard: legit urgent", "hr", "Urgent: submit your documents today", "Hi {name}, please submit your onboarding documents to HR by {day} through the intranet: https://intranet.example.com/docs/{n}. Thank you!"),
]
PHISH = [
    ("fake account verification", "security-alert", "URGENT: Verify your account immediately", "Dear customer, we detected unauthorized activity. Your account will be suspended unless you verify your password now: {url}"),
    ("fake invoice", "billing", "Invoice due - payment overdue #{n}", "Dear client, your invoice #{n} shows an outstanding payment. Open the attached file and pay immediately: {url}"),
    ("fake prize", "rewards", "Congratulations! Claim your prize", "You have won a free gift! Claim your prize within 24 hours and confirm your personal details: {url}"),
    ("fake password expiration", "it-desk", "Your password expires today", "Dear user, your password expires today. Update your password to avoid being locked out: {url}"),
    ("fake delivery", "delivery", "Package delivery failed", "Dear customer, delivery failed. Confirm your identity and card number to reschedule: {url}"),
    ("fake HR request", "hr-team", "Salary review - confirm details", "Dear employee, verify your account and confirm your personal details for payroll: {url}"),
    ("fake executive request", "ceo-office", "Quick favour needed", "Hi {name}, I am in a meeting. Buy gift card codes right away and send them to me. Act now: {url}"),
    ("hard: polite phish", "support", "Account notice {n}", "Hello {name}, please review your account settings when you have a moment: {url}"),
]
ATTACH_PHISH = ["invoice.pdf.exe", "statement.zip", "update.scr", "form.docm", "", "", ""]
ATTACH_LEGIT = ["agenda.pdf", "schedule.xlsx", "", "", ""]


def _phish_url():
    d = random.choice(PHISH_DOMAINS)
    return random.choice([f"http://198.51.100.{random.randint(2, 250)}/verify-account",
                          f"http://{d}/login/verify", f"http://secure-login.{d}/update",
                          f"http://short.example.net/x{random.randint(100, 999)}"])


def _fill(t, **kw):
    return t.format(n=random.randint(100, 9999), name=random.choice(NAMES), day=random.choice(DAYS), **kw)


def generate(rows_per_class=300, out_path=None):
    out_path = out_path or os.path.join(os.path.dirname(__file__), "phishing_email_dataset.csv")
    rows = []
    for i in range(rows_per_class * 2):
        phish = i % 2 == 1
        cat, local, subj, body = random.choice(PHISH if phish else LEGIT)
        dom = random.choice(PHISH_DOMAINS if phish else LEGIT_DOMAINS)
        url = _phish_url() if phish else ""
        body_f = _fill(body, url=url)
        urls = " ".join(u for u in body_f.split() if u.startswith("http"))
        rows.append({"email_id": i + 1, "sender": f"{local}@{dom}", "sender_domain": dom,
                     "subject": _fill(subj), "body": body_f, "urls": urls,
                     "attachment_name": random.choice(ATTACH_PHISH if phish else ATTACH_LEGIT),
                     "label": "PHISHING" if phish else "LEGITIMATE"})
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader(); w.writerows(rows)
    return out_path, len(rows)


if __name__ == "__main__":
    print("Wrote %s (%d rows)" % generate())
