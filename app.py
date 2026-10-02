"""Phishing Email Detection & Awareness Dashboard (Streamlit).
Run:  streamlit run app.py
All user text is shown with Streamlit text widgets (never raw HTML) to avoid XSS.
"""
from email import policy
from email.parser import BytesParser

import pandas as pd
import streamlit as st

from backend import database as db
from backend.services.risk_engine import analyze_email
from backend.utils.validation import MAX_UPLOAD_BYTES, validate_inputs
from ml.predict import model_available

st.set_page_config(page_title="Phishing Detection Dashboard", page_icon="🛡️", layout="wide")
page = st.sidebar.radio("Menu", ["Email Analyzer", "Dashboard", "History", "Awareness"])
st.sidebar.caption("Educational tool. Use synthetic or authorized data only.")

SAMPLES = {
    "(none)": ("", "", "", ""),
    "Synthetic phishing": ("security-alert@account-check.invalid.test", "URGENT: Verify Your Account Immediately",
        "Dear customer, we detected unauthorized activity. Your account will be suspended unless you "
        "verify your password immediately: http://198.51.100.10/verify-account", ""),
    "Legitimate": ("training@example.org", "Cybersecurity Workshop Reminder",
        "Hi team, this is a reminder that the workshop is on Friday at 3 PM in Room 204. See you there.", ""),
}


def parse_eml(data):
    msg = BytesParser(policy=policy.default).parsebytes(data)
    part = msg.get_body(preferencelist=("plain",))
    body = part.get_content() if part else ""
    atts = [a.get_filename() or "" for a in msg.iter_attachments()]
    return str(msg.get("From", "")), str(msg.get("Subject", "")), body, (atts[0] if atts else "")


if page == "Email Analyzer":
    st.title("🛡️ Email Analyzer")
    choice = st.selectbox("Load a safe sample", list(SAMPLES))
    up = st.file_uploader("...or upload a safe .txt / .eml sample", type=["txt", "eml"])
    s0, sub0, b0, a0 = SAMPLES[choice]
    if up is not None:
        if up.size > MAX_UPLOAD_BYTES:
            st.error("File too large (max 200 KB).")
        elif up.name.endswith(".eml"):
            s0, sub0, b0, a0 = parse_eml(up.getvalue())
        else:
            b0 = up.getvalue().decode("utf-8", "replace")
    key = f"{choice}-{up.name if up else ''}"
    c1, c2 = st.columns(2)
    sender = c1.text_input("Sender", s0, key="s" + key)
    subject = c2.text_input("Subject", sub0, key="u" + key)
    body = st.text_area("Body", b0, height=180, key="b" + key)
    c3, c4 = st.columns(2)
    attach = c3.text_input("Attachment filename (optional)", a0, key="a" + key)
    display = c4.text_input("Display name (optional)", key="d" + key)
    use_ml = st.checkbox("Use ML model too (hybrid)", value=model_available(), disabled=not model_available())
    if st.button("ANALYZE EMAIL", type="primary"):
        try:
            validate_inputs(sender, subject, body)
        except ValueError as e:
            st.error(str(e)); st.stop()
        r = analyze_email(sender, subject, body, attach, display or None, use_ml=use_ml)
        db.save_analysis(r, subject)
        icon = {"HIGH RISK / LIKELY PHISHING": "🔴", "SUSPICIOUS": "🟠", "MODERATE RISK": "🟡"}.get(r["classification"], "🟢")
        m1, m2 = st.columns(2)
        m1.metric("Phishing risk score", f"{r['score']}/100")
        m2.metric("Classification", f"{icon} {r['classification']}")
        if r["ml_probability"] is not None:
            st.caption(f"Rule score {r['rule_score']}/100 · ML probability {r['ml_probability']:.0%} (a probability, not certainty)")
        st.subheader("Why?")
        for x in r["reasons"] or [{"indicator": "none", "points": 0, "detail": "No indicators fired."}]:
            st.write(f"✓ **{x['indicator'].replace('_', ' ')}** (+{x['points']}) - {x['detail']}")
        st.subheader("Sender analysis")
        st.write(f"Sender risk: {r['sender']['score']}/100")
        for f in r["sender"]["findings"]: st.write("- " + f)
        st.subheader("URL analysis (static - links are never opened)")
        for u in r["urls"]:
            st.code(u["url_safe"]); st.write(f"URL risk: {u['score']}/100")
            for f in u["findings"]: st.write("- " + f)
        if not r["urls"]: st.write("No URLs found.")
        if attach:
            st.subheader("Attachment analysis (filename only)")
            st.write(f"Risk: {r['attachment']['score']}/100")
            for f in r["attachment"]["findings"]: st.write("- " + f)
        st.subheader("Recommended actions")
        for a in r["recommendations"]: st.write("- " + a)
        st.info("Scores are a risk estimate that supports human judgment. One indicator never proves phishing.")

elif page == "Dashboard":
    st.title("📊 Dashboard")
    df = pd.DataFrame(db.list_analyses())
    if df.empty:
        st.info("No analyses yet - analyze an email first.")
    else:
        k = st.columns(5)
        k[0].metric("Total analyzed", len(df))
        k[1].metric("Likely phishing", int((df.classification == "HIGH RISK / LIKELY PHISHING").sum()))
        k[2].metric("Suspicious", int((df.classification == "SUSPICIOUS").sum()))
        k[3].metric("Low risk", int((df.classification == "LOW RISK").sum()))
        k[4].metric("Avg score", round(df.risk_score.mean(), 1))
        a, b = st.columns(2)
        a.subheader("Classification distribution"); a.bar_chart(df.classification.value_counts())
        flagged = df.classification.isin(["SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"]).map({True: "Flagged", False: "Not flagged"})
        b.subheader("Flagged vs not flagged"); b.bar_chart(flagged.value_counts())
        c, d = st.columns(2)
        ind = pd.DataFrame(db.indicator_counts())
        c.subheader("Top detected indicators")
        if not ind.empty: c.bar_chart(ind.set_index("indicator_type")["n"])
        d.subheader("Risk score distribution")
        d.bar_chart(pd.cut(df.risk_score, [-1, 20, 40, 70, 100], labels=["0-20", "21-40", "41-70", "71-100"]).value_counts().sort_index())
        e, f = st.columns(2)
        e.subheader("Detection trend")
        e.line_chart(df.assign(day=df.created_at.str[:10]).groupby("day").size())
        kw = pd.DataFrame(db.indicator_counts("keyword"))
        f.subheader("Most common suspicious keywords")
        if not kw.empty: f.bar_chart(kw.set_index("description")["n"])

elif page == "History":
    st.title("🗂️ Analysis history")
    c1, c2, c3 = st.columns(3)
    cls = c1.selectbox("Classification", ["All", "LOW RISK", "MODERATE RISK", "SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"])
    q = c2.text_input("Search subject/domain")
    sort = c3.selectbox("Sort", ["newest", "score_desc", "score_asc"])
    rows = db.list_analyses(None if cls == "All" else cls, q or None, sort)
    st.dataframe(pd.DataFrame(rows), use_container_width=True)
    if rows:
        aid = st.selectbox("View analysis", [r["analysis_id"] for r in rows])
        st.json(db.get_analysis(aid))
        if st.button("Delete this analysis"):
            db.delete_analysis(aid); st.rerun()

else:
    st.title("🎓 How to Spot a Phishing Email")
    tips = ["Sender address - does it match the organisation?", "Domain spelling - look for paypa1-style tricks",
            "Unexpected urgency", "Suspicious links - hover before you click", "Credential requests",
            "Unexpected attachments", "Generic greetings", "Unusual payment requests", "Threatening language",
            "Context - were you expecting this email?"]
    for i, t in enumerate(tips, 1):
        st.write(f"**{i}.** {t}")
    st.subheader("✅ Before You Click")
    for item in ["I recognise the sender and the address is spelled correctly", "I was expecting this message",
                 "The link destination matches the text", "It is not asking for a password or personal data",
                 "There is no unusual pressure or threat", "I can verify it through an official channel"]:
        st.checkbox(item, key=item)
    st.caption("HTTPS (the padlock) does NOT mean a site is trustworthy.")
