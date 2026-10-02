"""Attachment analyzer: looks at the FILENAME only. Files are never opened or executed."""
import os

DANGEROUS = {"exe", "scr", "bat", "cmd", "js", "vbs", "ps1", "msi", "jar", "com", "pif", "hta"}
ARCHIVES = {"zip", "rar", "7z", "iso", "img"}
MACRO_DOCS = {"docm", "xlsm", "pptm"}
DOC_TYPES = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}
SUSPICIOUS_THRESHOLD = 30


def analyze_attachment(filename):
    name = os.path.basename((filename or "").strip().lower())
    if not name:
        return {"filename": "", "score": 0, "findings": [], "suspicious": False}
    parts = name.split(".")
    exts = parts[1:]
    last = exts[-1] if exts else ""
    findings, score = [], 0
    if last in DANGEROUS:
        score += 60
        findings.append(f"Executable/script extension (.{last})")
        if len(exts) >= 2 and exts[-2] in DOC_TYPES:
            score += 30
            findings.append("Double extension disguises a program as a document")
    elif last in MACRO_DOCS:
        score += 30
        findings.append(f"Macro-enabled document (.{last})")
    elif last in ARCHIVES:
        score += 20
        findings.append(f"Archive file (.{last}) can hide contents")
    score = min(score, 100)
    return {"filename": name, "score": score, "findings": findings,
            "suspicious": score >= SUSPICIOUS_THRESHOLD}
