"""Input validation (limits protect the app; display uses Streamlit text widgets, never raw HTML)."""
MAX_BODY = 20000
MAX_SUBJECT = 300
MAX_UPLOAD_BYTES = 200_000


def validate_inputs(sender, subject, body):
    if not (subject or "").strip() and not (body or "").strip():
        raise ValueError("Provide at least a subject or a body.")
    if len(body or "") > MAX_BODY:
        raise ValueError(f"Body too long (max {MAX_BODY} characters).")
    if len(subject or "") > MAX_SUBJECT:
        raise ValueError(f"Subject too long (max {MAX_SUBJECT} characters).")
    return True
