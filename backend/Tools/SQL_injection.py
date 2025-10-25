# Tools/SQL_injection.py
"""
Conservative passive SQLi check: sends a harmless single-quote token and checks
for common DB error messages in the response.
Non-destructive but active; only use with authorization.
"""

from ._common import _normalize_url, _safe_get
import time
from urllib.parse import urlencode

_DB_ERRORS = [
    "mysql", "syntax error", "sql", "odbc", "pdo", "sqlite",
    "pg_query", "unknown column", "sqlstate", "database error",
    "unterminated quoted string", "invalid query"
]

def check_sql_injection(url: str, timeout: int = 10):
    start = time.time()
    url = _normalize_url(url)
    try:
        # Build a harmless probe parameter. urlencode will encode the quote to %27.
        probe_suffix = ("&" if "?" in url else "?") + urlencode({"v": "'"})
        probe = url + probe_suffix

        resp, err = _safe_get(probe, timeout=timeout)
        if err:
            return {"error": "Request failed", "details": err}

        if resp is None:
            return {"error": "No response", "details": "No HTTP response received from target."}

        text = (resp.text or "").lower()
        found = [e for e in _DB_ERRORS if e in text]

        severity = "HIGH" if found else "LOW"
        duration_ms = int((time.time() - start) * 1000)

        return {
            "name": "SQL Injection (passive heuristic)",
            "severity": severity,
            "description": "Detected database error strings in response." if found else "No DB error strings detected for harmless payload.",
            "fix": "Use parameterized queries (prepared statements), input validation, and least-privilege DB accounts.",
            "evidence": found,
            "status_code": resp.status_code if resp is not None else None,
            "text_snippet": (resp.text[:800] if resp and resp.text else ""),
            "_meta": {"scan_duration_ms": duration_ms}
        }
    except Exception as ex:
        # keep format same: return an error dict (other components expect this shape)
        return {"error": "Exception", "details": str(ex)}

def scan(url: str, timeout: int = 10):
    return check_sql_injection(url, timeout=timeout)

def run(url: str, timeout: int = 10):
    return scan(url, timeout=timeout)
