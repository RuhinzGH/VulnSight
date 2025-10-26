# Tools/ClickJacking_Tester.py
"""
Safe Clickjacking header checker.
Non-destructive: only GETs the target and checks X-Frame-Options + CSP frame-ancestors.

Return format preserved so frontend expects the same keys:
{
  "name": ...,
  "severity": ...,
  "description": ...,
  "fix": ...,
  "references": [...],
  "response_headers": {...},
  "status_code": int,
  "text_snippet": "...",
  "_meta": {"scan_duration_ms": int, "module_callable": "check_clickjacking"}
}
"""

from typing import Dict, Any, Optional
import time
from urllib.parse import urlparse
from ._common import _normalize_url, _safe_get, _make_base_result
import re

def _parse_frame_ancestors(csp_value: str) -> Optional[str]:
    """
    Robustly extracts the frame-ancestors directive value from a Content-Security-Policy header.
    Returns the value string (e.g. "'self' https://trusted.example") or None if not present.
    """
    if not csp_value:
        return None
    # split into directives and find the one that starts with frame-ancestors
    directives = [d.strip() for d in csp_value.split(';') if d.strip()]
    for d in directives:
        parts = d.split(None, 1)
        if len(parts) >= 1 and parts[0].lower() == "frame-ancestors":
            return parts[1].strip() if len(parts) == 2 else ""
    return None

def _is_frame_ancestors_safe(fa_value: str) -> bool:
    """
    Determine if the frame-ancestors directive indicates protection.
    We treat explicit 'none' or 'self' as safe; explicit origin patterns (https://...) are also safe.
    Avoid naive substring matches.
    """
    if not fa_value:
        return False
    lower = fa_value.lower()
    if "'none'" in lower or "'self'" in lower:
        return True
    # explicit origin patterns (http or https with domain) - treat as safe because authors restricted to specific origins
    if re.search(r"https?://[^\s;']+", fa_value):
        return True
    return False

def check_clickjacking(url: str, timeout: int = 10) -> Dict[str, Any]:
    start = time.time()
    url = _normalize_url(url)
    base = _make_base_result("Clickjacking")
    try:
        resp, err = _safe_get(url, timeout=timeout)
        if err:
            # keep consistent error payload shape used elsewhere
            return {"error": "Request failed", "details": err}

        # Normalize headers to lowercase keys for robust lookups, but preserve original headers for response_headers
        raw_headers = dict(resp.headers or {})
        headers_lower = {k.lower(): v for k, v in raw_headers.items()}

        xfo = headers_lower.get("x-frame-options")
        csp = headers_lower.get("content-security-policy")

        notes = []
        safe = False

        if xfo:
            notes.append(f"X-Frame-Options: {xfo}")
            # normalize and check canonical safe values
            xfoval = xfo.strip().upper()
            if xfoval in ("DENY", "SAMEORIGIN"):
                safe = True
        else:
            notes.append("X-Frame-Options: MISSING")

        # parse CSP frame-ancestors robustly
        fa = _parse_frame_ancestors(csp) if csp else None
        notes.append(f"CSP frame-ancestors: {fa if fa is not None else 'none'}")

        if _is_frame_ancestors_safe(fa or ""):
            safe = True

        # severity logic: keep same keys as before (LOW, MEDIUM, HIGH)
        severity = "LOW" if safe else ("HIGH" if (not xfo and not fa) else "MEDIUM")

        duration_ms = int((time.time() - start) * 1000)
        return {
            "name": "Clickjacking",
            "severity": severity,
            "description": "; ".join(notes),
            "fix": "Set X-Frame-Options to DENY or SAMEORIGIN and/or add CSP frame-ancestors for allowed origins.",
            "references": ["https://owasp.org/www-community/attacks/Clickjacking"],
            "response_headers": raw_headers,
            "status_code": getattr(resp, "status_code", None),
            "text_snippet": (resp.text[:800] if getattr(resp, "text", None) else ""),
            "_meta": {"scan_duration_ms": duration_ms, "module_callable": "check_clickjacking"}
        }
    except Exception as e:
        return {"error": "Exception", "details": str(e)}

# compatibility wrappers (unchanged)
def scan(url: str, timeout: int = 10):
    return check_clickjacking(url, timeout=timeout)

def run(url: str, timeout: int = 10):
    return scan(url, timeout=timeout)
