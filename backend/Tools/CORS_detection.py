# Tools/CORS_detection.py
"""
Conservative CORS analysis. Non-destructive: it sends an OPTIONS preflight and a simple GET.
Does not attempt to inject origin headers that might cause side-effects except a harmless Origin header.
Return shape preserved for frontend compatibility.
"""

from ._common import _normalize_url, _safe_get, _make_base_result
import time
import requests
from typing import Dict, Any, Optional

_TEST_ORIGIN = "https://example.com"
_USER_AGENT = "VulnSight-CORS-Checker/1.0"

def _extract_header_ci(headers: Dict[str, str], name: str) -> Optional[str]:
    """Case-insensitive header lookup; returns header value or None."""
    if not headers:
        return None
    # requests.Response.headers already provides case-insensitive mapping, but being explicit is safe
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None

def check_cors(url: str, timeout: int = 10) -> Dict[str, Any]:
    start = time.time()
    url = _normalize_url(url)

    # Try OPTIONS first (preflight) — non-destructive and useful to inspect allowed methods/headers
    try:
        opt_headers = {"User-Agent": _USER_AGENT, "Origin": _TEST_ORIGIN}
        opt_resp, opt_err = _safe_get(url, timeout=timeout, allow_redirects=True)
        # Note: _safe_get may perform GET by default; if you have an internal helper for OPTIONS, adapt here.
        # We'll still send a direct requests.options below for clarity.
    except Exception:
        opt_resp = None

    # Send explicit OPTIONS using requests (safe — no payload, no destructive action)
    try:
        options_resp = requests.options(url, headers={"User-Agent": _USER_AGENT, "Origin": _TEST_ORIGIN}, timeout=timeout, allow_redirects=True)
    except Exception:
        options_resp = None

    # Send a GET with Origin header to test request-time behavior
    try:
        get_resp, get_err = _safe_get(url, timeout=timeout)
        # If _safe_get doesn't include Origin, perform a small direct GET with Origin header (safe)
        # We'll use requests.get with Origin so servers that depend on it can reflect it.
        get_with_origin = None
        try:
            get_with_origin = requests.get(url, headers={"User-Agent": _USER_AGENT, "Origin": _TEST_ORIGIN}, timeout=timeout, allow_redirects=True)
        except Exception:
            get_with_origin = None
    except Exception as e:
        return {"error": "Request failed", "details": str(e)}

    # Prefer the GET-with-origin response for header checks if available
    resp = get_with_origin or get_resp
    if resp is None:
        return {"error": "No response", "details": "Failed to fetch resource"}

    headers = dict(resp.headers or {})

    # extract relevant CORS headers (case-insensitive)
    acao = _extract_header_ci(headers, "Access-Control-Allow-Origin")
    acac = _extract_header_ci(headers, "Access-Control-Allow-Credentials")
    acam = _extract_header_ci(headers, "Access-Control-Allow-Methods")
    acah = _extract_header_ci(headers, "Access-Control-Allow-Headers")

    notes = []
    severity = "LOW"

    if acao:
        notes.append(f"Access-Control-Allow-Origin: {acao}")
        # wildcard is dangerous if server also allows credentials or echoes origin
        if acao.strip() == "*":
            severity = "HIGH"
            notes.append("Wildcard origin detected — risky if any sensitive data is returned or if credentials are expected.")
        else:
            # check if ACAO echoes the origin we sent (origin reflection)
            if acao.strip() == _TEST_ORIGIN:
                # reflected origin — higher risk especially if credentials allowed
                severity = "HIGH"
                notes.append("Access-Control-Allow-Origin appears to reflect the incoming Origin header (origin reflection).")
            else:
                # specific allowed origin (not an exact reflection) — likely medium
                severity = "MEDIUM"
                notes.append("Specific origin allowed (not wildcard).")

    else:
        notes.append("No Access-Control-Allow-Origin header present (no cross-origin access allowed).")
        severity = "LOW"

    # Credentials: if server allows credentials, increase severity when paired with reflection or wildcard
    if acac and acac.strip().lower() == "true":
        notes.append("Access-Control-Allow-Credentials: true")
        if severity == "HIGH":
            notes.append("Credentials allowed together with wildcard/reflection -> critical risk for cross-origin token/cookie theft.")
        else:
            # raise MEDIUM -> HIGH if previously MEDIUM
            severity = "HIGH" if severity == "MEDIUM" else severity

    # Add info about allowed methods/headers from OPTIONS if present
    if options_resp is not None:
        o_headers = dict(options_resp.headers or {})
        o_acam = _extract_header_ci(o_headers, "Access-Control-Allow-Methods")
        o_acah = _extract_header_ci(o_headers, "Access-Control-Allow-Headers")
        if o_acam:
            notes.append(f"Preflight methods: {o_acam}")
        if o_acah:
            notes.append(f"Preflight headers: {o_acah}")

    duration_ms = int((time.time() - start) * 1000)

    return {
        "name": "CORS Misconfiguration",
        "severity": severity,
        "description": "; ".join(notes),
        "fix": "Restrict Access-Control-Allow-Origin to a short list of trusted origins. Do not echo the Origin header blindly. Do not enable Access-Control-Allow-Credentials unless you strictly trust origins and use robust authentication.",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS", "https://owasp.org/www-community/controls/CORS_implementation_checklist"],
        "status_code": getattr(resp, "status_code", None),
        "response_headers": headers,
        "text_snippet": (resp.text[:800] if getattr(resp, "text", None) else ""),
        "_meta": {"scan_duration_ms": duration_ms}
    }

def scan(url: str, timeout: int = 10):
    return check_cors(url, timeout=timeout)

def run(url: str, timeout: int = 10):
    return scan(url, timeout=timeout)
