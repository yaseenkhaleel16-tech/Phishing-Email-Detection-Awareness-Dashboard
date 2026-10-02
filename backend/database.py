"""SQLite storage. Stores metadata only (sender domain, subject, score) - NOT the email body."""
import os
import sqlite3
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses(
  analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_domain TEXT, subject TEXT, risk_score INTEGER, classification TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS indicators(
  indicator_id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  indicator_type TEXT, description TEXT, severity TEXT);
CREATE TABLE IF NOT EXISTS url_analyses(
  url_analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
  analysis_id INTEGER REFERENCES analyses(analysis_id) ON DELETE CASCADE,
  url_safe_representation TEXT, risk_score INTEGER, findings TEXT);
"""
SORTS = {"newest": "created_at DESC", "score_desc": "risk_score DESC", "score_asc": "risk_score ASC"}


def _conn():
    path = os.environ.get("PHISH_DB", "data/analyses.db")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(SCHEMA)
    return conn


def _severity(points):
    return "high" if points >= 20 else "medium" if points >= 10 else "low"


def save_analysis(result, subject):
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO analyses(sender_domain,subject,risk_score,classification,created_at) VALUES(?,?,?,?,?)",
            (result["sender"]["domain"], (subject or "")[:200], result["score"],
             result["classification"], datetime.now(timezone.utc).isoformat(timespec="seconds")))
        aid = cur.lastrowid
        for r in result["reasons"]:
            c.execute("INSERT INTO indicators(analysis_id,indicator_type,description,severity) VALUES(?,?,?,?)",
                      (aid, r["indicator"], r["detail"], _severity(r["points"])))
        for f in result["content"]["findings"]:
            for phrase in f["matches"]:
                c.execute("INSERT INTO indicators(analysis_id,indicator_type,description,severity) VALUES(?,?,?,?)",
                          (aid, "keyword", phrase, "low"))
        for u in result["urls"]:
            c.execute("INSERT INTO url_analyses(analysis_id,url_safe_representation,risk_score,findings) VALUES(?,?,?,?)",
                      (aid, u["url_safe"], u["score"], "; ".join(u["findings"])))
    return aid


def list_analyses(classification=None, search=None, sort="newest"):
    q, args = "SELECT * FROM analyses WHERE 1=1", []
    if classification:
        q += " AND classification=?"; args.append(classification)
    if search:
        q += " AND (subject LIKE ? OR sender_domain LIKE ?)"; args += [f"%{search}%"] * 2
    q += " ORDER BY " + SORTS.get(sort, SORTS["newest"])  # whitelist -> no SQL injection
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args)]


def get_analysis(aid):
    with _conn() as c:
        row = c.execute("SELECT * FROM analyses WHERE analysis_id=?", (aid,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["indicators"] = [dict(r) for r in c.execute("SELECT * FROM indicators WHERE analysis_id=?", (aid,))]
        d["urls"] = [dict(r) for r in c.execute("SELECT * FROM url_analyses WHERE analysis_id=?", (aid,))]
        return d


def delete_analysis(aid):
    with _conn() as c:
        return c.execute("DELETE FROM analyses WHERE analysis_id=?", (aid,)).rowcount > 0


def indicator_counts(indicator_type=None, limit=10):
    q, args = "SELECT indicator_type, description, COUNT(*) n FROM indicators", []
    if indicator_type == "keyword":
        q += " WHERE indicator_type='keyword' GROUP BY description"
    else:
        q += " WHERE indicator_type!='keyword' GROUP BY indicator_type"
    q += " ORDER BY n DESC LIMIT ?"; args.append(limit)
    with _conn() as c:
        return [dict(r) for r in c.execute(q, args)]
