# Phishing Email Detection & Awareness Dashboard

Defensive cybersecurity dashboard for analyzing **synthetic** email content, sender patterns, URLs, attachment names and social-engineering language to produce **explainable phishing risk scores**.

> This project is designed for cybersecurity education and defensive analysis using synthetic or authorized data.

## Features
- Sender, content, URL (static, never visited) and attachment (filename only) analyzers
- Rule-based risk score (0-100) with reasons + recommended actions
- Optional ML (TF-IDF + Logistic Regression / Naive Bayes / Random Forest) and hybrid score
- SQLite analysis history (metadata only, no email bodies), search/filter/sort
- Dashboard with 6 charts + phishing-awareness module
- 29 automated tests

## Quick start
```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python data/generate_dataset.py      # synthetic dataset
python -m ml.train_model             # optional ML model
python -m pytest -q                  # run tests
streamlit run app.py                 # open the dashboard
```

## Architecture
Input -> validation -> Sender / Content / URL / Attachment analyzers -> risk engine (+ optional ML) -> classification -> explanation + recommendations -> SQLite -> dashboard.

## Risk scoring
Weights (sender +15, urgency +10, credential +20, URL +20, attachment +25, generic greeting +5, fear +10, financial/reward/personal info +10 each), capped at 100. Bands: 0-20 LOW, 21-40 MODERATE, 41-70 SUSPICIOUS, 71-100 HIGH. **These are project assumptions**, not universal rules; calibrate on validation data.

## Limitations (be honest in interviews)
- The dataset is template-generated, so ML metrics (100% here) are inflated and do NOT reflect real-world performance.
- Keyword rules cause false positives (a genuine "Urgent: submit documents" HR email) and false negatives (polished phishing with no obvious signals).
- No email-header (SPF/DKIM/DMARC) analysis or reputation lookups yet.

## Safety
Synthetic data only, fictional domains/reserved IPs, no attachments executed, no URLs visited, no credential collection, user text rendered as plain text (XSS-safe), input/upload limits.

## Future improvements
Header analysis, SPF/DKIM/DMARC, URL/domain reputation, better NLP, analyst feedback loop, SIEM/ticket integration.
<img width="1600" height="1200" alt="WhatsApp Image 2026-10-02 at 08 22 27" src="https://github.com/user-attachments/assets/6af657d8-55db-45ee-b9d5-705f7ddba0d5" />
<img width="1600" height="1200" alt="WhatsApp Image 2026-10-02 at 08 22 28" src="https://github.com/user-attachments/assets/1a30dd4c-6332-44fa-920a-a7422266fed1" />
<img width="1600" height="1200" alt="WhatsApp Image 2026-10-02 at 08 22 28 (1)" src="https://github.com/user-attachments/assets/f2562d57-a6ad-4497-8318-1bc5ec71139f" />
<img width="1600" height="1200" alt="WhatsApp Image 2026-10-02 at 08 22 28 (2)" src="https://github.com/user-attachments/assets/ad5f8003-7ec1-4a42-9521-092c253e6520" />
[README.md](https://github.com/user-attachments/files/32941185/README.md)

