# Tools/XSS.py
"""
Conservative XSS reflector check: sends a harmless unique token and checks whether it's present in the response.
This is an active check but non-destructive: token contains no script; it simply checks reflection.
Requires authorization to scan.
"""

from ._common import _normalize_url, _safe_get
import time
import uuid
from urllib.parse import urlencode

def check_xss_reflection(url: str, timeout: int = 10):
    start = time.time()
    url = _normalize_url(url)
    token = "vulnsight-" + uuid.uuid4().hex[:8]
    probe = url + ("&" if "?" in url else "?") + urlencode({"vuln": token})

    # perform request safely via shared helper
    resp, err = _safe_get(probe, timeout=timeout)
    if err:
        return {"error": "Request failed", "details": err}

    # Defensive checks: ensure we have text and it's not huge/binary
    body = ""
    try:
        if resp is None:
            return {"error": "No response", "details": "Request returned no response object"}
        # some responses may be binary; check Content-Type
        ctype = (resp.headers.get("Content-Type") or "").lower()
        if "text" not in ctype and "html" not in ctype and "json" not in ctype:
            body = ""
        else:
            body = resp.text or ""
    except Exception:
        body = resp.text[:1024] if getattr(resp, "text", None) else ""

    found = token in body
    severity = "HIGH" if found else "LOW"
    duration_ms = int((time.time() - start) * 1000)

    return {
        "name": "Reflected XSS (safe reflection check)",
        "severity": severity,
        "description": "Detected reflection of innocent token in response." if found else "No reflection of safe token detected.",
        "fix": "Sanitize output and encode user-supplied data before rendering.",
        "evidence": [{"token": token}] if found else [],
        "status_code": getattr(resp, "status_code", None),
        "text_snippet": body[:800] if body else "",
        "_meta": {"scan_duration_ms": duration_ms}
    }

def scan(url: str, timeout: int = 10):
    return check_xss_reflection(url, timeout=timeout)

def run(url: str, timeout: int = 10):
    return scan(url, timeout=timeout)
