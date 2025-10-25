"""
Check cookie attributes for session cookies (HttpOnly, Secure, SameSite).
Non-destructive: inspects Set-Cookie headers only.
"""

from ._common import _normalize_url, _safe_get
import time
from http.cookies import SimpleCookie

def check_cookies(url: str, timeout: int = 10):
    start = time.time()
    url = _normalize_url(url)
    resp, err = _safe_get(url, timeout=timeout)
    if err:
        return {"error": "Request failed", "details": err}

    cookies = resp.headers.get("Set-Cookie")
    insecure = []

    if cookies:
        cookie = SimpleCookie()
        cookie.load(cookies)
        raw_set = resp.headers.get_all("Set-Cookie") if hasattr(resp.headers, "get_all") else [cookies]

        for raw in raw_set:
            low = raw.lower()
            missing_flags = []
            # Basic Secure & HttpOnly checks
            if "secure" not in low:
                missing_flags.append("Secure")
            if "httponly" not in low:
                missing_flags.append("HttpOnly")

            # Check SameSite presence & value
            if "samesite" not in low:
                missing_flags.append("SameSite (missing)")
            elif "samesite=none" in low:
                missing_flags.append("SameSite=None (risky)")

            if missing_flags:
                insecure.append({
                    "cookie": raw[:200],
                    "issues": missing_flags
                })

    severity = "HIGH" if insecure else "LOW"
    duration_ms = int((time.time() - start) * 1000)

    return {
        "name": "Insecure Cookies",
        "severity": severity,
        "description": (
            f"Cookies missing secure attributes: {len(insecure)} items."
            if insecure else
            "No insecure cookies detected (based on Set-Cookie)."
        ),
        "fix": (
            "Set Secure, HttpOnly, and SameSite attributes for session cookies. "
            "Recommended: SameSite=Strict with Secure and HttpOnly enabled."
        ),
        "evidence": insecure,
        "status_code": resp.status_code,
        "_meta": {"scan_duration_ms": duration_ms}
    }

def scan(url: str, timeout: int = 10):
    return check_cookies(url, timeout=timeout)

def run(url: str, timeout: int = 10):
    return scan(url, timeout=timeout)
