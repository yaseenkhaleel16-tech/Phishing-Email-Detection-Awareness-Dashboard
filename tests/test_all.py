import os
import pytest
from backend import database as db
from backend.services.attachment_analyzer import analyze_attachment
from backend.services.content_analyzer import analyze_email_content
from backend.services.risk_engine import analyze_email, classify
from backend.services.sender_analyzer import analyze_sender
from backend.services.url_analyzer import analyze_url, defang, extract_urls
from backend.utils.validation import validate_inputs

PHISH = dict(sender="security-alert@account-check.invalid.test", subject="URGENT: Verify Your Account Immediately",
             body="Dear customer, unauthorized activity found. Your account will be suspended unless you verify "
                  "your password immediately: http://198.51.100.10/verify-account")
LEGIT = dict(sender="training@example.org", subject="Cybersecurity Workshop Reminder",
             body="Hi team, reminder that the workshop is on Friday at 3 PM in Room 204. See you there.")


def inds(r): return {x["indicator"] for x in r["reasons"]}

def test_t01_legit_email_low(): r = analyze_email(**LEGIT); assert r["classification"] == "LOW RISK" and r["score"] <= 20
def test_t02_urgent_email(): assert "urgency" in inds(analyze_email("a@example.com", "Act now", "Act now, immediately."))
def test_t03_credential_request(): assert "credential_request" in inds(analyze_email("a@example.com", "Hi", "Please verify your password."))
def test_t04_financial(): assert "financial_pressure" in inds(analyze_email("a@example.com", "Hi", "You have an outstanding payment."))
def test_t05_generic_greeting(): assert "generic_greeting" in inds(analyze_email("a@example.com", "Hi", "Dear customer, hello."))
def test_t06_safe_url(): assert analyze_url("https://www.example.com/news")["score"] == 0
def test_t07_raw_ip_url(): u = analyze_url("http://198.51.100.10/verify-account"); assert u["is_ip"] and u["score"] >= 50
def test_t08_non_https(): assert analyze_url("http://www.example.com")["score"] == 15
def test_t09_excess_subdomains(): assert analyze_url("https://a.b.c.d.example.com/")["subdomain_count"] >= 3
def test_t10_url_keyword(): assert "login" in analyze_url("https://example.com/login/verify")["keywords"]
def test_t11_no_url(): assert extract_urls("hello") == []
def test_t12_multiple_urls(): assert len(extract_urls("http://a.example.com and https://b.example.org/x")) == 2
def test_t13_normal_attachment(): assert analyze_attachment("report.pdf")["score"] == 0
def test_t14_exe_attachment(): assert analyze_attachment("setup.exe")["suspicious"]
def test_t15_double_extension(): a = analyze_attachment("invoice.pdf.exe"); assert a["score"] >= 90
def test_t16_empty_subject(): assert analyze_email("a@example.com", "", "hello there")["score"] >= 0
def test_t17_empty_body(): assert analyze_email("a@example.com", "hello", "")["score"] >= 0
def test_t18_invalid_sender(): assert analyze_sender("not-an-email")["score"] >= 40
def test_t19_uppercase_ratio(): assert analyze_email_content("", "URGENT ACT NOW")["uppercase_ratio"] > 0.9
def test_t20_exclamations(): assert analyze_email_content("Hi!!", "Wow!!")["exclamation_count"] == 4

def test_t21_score_boundaries():
    assert classify(20) == "LOW RISK" and classify(21) == "MODERATE RISK" and classify(40) == "MODERATE RISK"
    assert classify(41) == "SUSPICIOUS" and classify(70) == "SUSPICIOUS" and classify(71).startswith("HIGH")

def test_t22_database_save(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISH_DB", str(tmp_path / "t.db"))
    aid = db.save_analysis(analyze_email(**PHISH), PHISH["subject"])
    got = db.get_analysis(aid)
    assert got["classification"].startswith("HIGH") and got["indicators"] and "body" not in got

def test_t23_input_validation():
    with pytest.raises(ValueError): validate_inputs("a@example.com", "", "")
    with pytest.raises(ValueError): validate_inputs("a@example.com", "x", "y" * 30000)

@pytest.mark.skipif(not os.path.exists("models/phishing_model.joblib"), reason="model not trained")
def test_t24_ml_prediction():
    from ml.predict import predict_proba
    assert 0 <= predict_proba(**{"sender": PHISH["sender"], "subject": PHISH["subject"], "body": PHISH["body"]}) <= 1

def test_t25_history_retrieval(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISH_DB", str(tmp_path / "t.db"))
    db.save_analysis(analyze_email(**PHISH), PHISH["subject"]); db.save_analysis(analyze_email(**LEGIT), LEGIT["subject"])
    assert len(db.list_analyses()) == 2
    assert len(db.list_analyses(classification="LOW RISK")) == 1
    assert db.list_analyses(sort="score_desc")[0]["risk_score"] >= db.list_analyses(sort="score_asc")[0]["risk_score"]
    assert len(db.list_analyses(search="workshop")) == 1

def test_t26_demo_phishing_high():
    r = analyze_email(**PHISH)
    assert r["classification"].startswith("HIGH")
    assert {"urgency", "credential_request", "suspicious_sender", "suspicious_url"} <= inds(r)

def test_t27_defang(): assert "http://" not in defang("http://198.51.100.10/x")
def test_t28_display_name_mismatch(): assert analyze_sender("a@example.com", display_name="ExampleBank Support")["suspicious"]
def test_t29_hr_urgent_false_positive_stays_low():
    r = analyze_email("hr@example.com", "Urgent: submit your documents today", "Hi Sam, please submit documents by Friday.")
    assert r["classification"] == "LOW RISK"  # one weak indicator alone must not flag an email
