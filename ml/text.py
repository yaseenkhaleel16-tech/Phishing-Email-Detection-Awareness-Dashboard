def build_text(sender, subject, body, attachment_name=""):
    """Combine fields into one string for TF-IDF. Keeps URLs/domains (useful evidence) intact."""
    return f"{sender or ''} {subject or ''} {body or ''} {attachment_name or ''}".lower()
