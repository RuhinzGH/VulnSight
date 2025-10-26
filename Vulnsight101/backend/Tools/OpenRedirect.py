# Tools/OpenRedirect.py
"""
Passive Open Redirect Detection
--------------------------------
Checks for the presence of common redirect parameters (e.g., ?next=, ?url=, etc.)
that might allow attackers to redirect users to external domains.

This is a **non-destructive** test — it does NOT follow or trigger real redirects.
"""

from ._common import _normalize_url, _safe_get
import time
from urllib.parse import urlparse, urlencode

# Common query parameters often used for redirects
_COMMON_PARAMS = ["next", "url", "redirect", "return", "r"]

def check_open_redirect(url: str, timeout: int = 10):
    start = time.time()
    url = _normalize_url(url)
    findings = []

    for param in _COMMON_PARAMS:
        parsed = urlparse(url)
        safe_target = f"{parsed.scheme}://{parsed.netloc}/"

        # Add the test parameter (?next=https://example.com/)
        probe = url + ("&" if "?" in url else "?") + urlencode({param: safe_target})

        try:
            # Do not follow redirects — just check response headers
            resp, err = _safe_get(probe, timeout=timeout, allow_redirects=False)
            if err or not resp:
                continue

            # If response status is a redirect (3xx), inspect Location header
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")

                # If redirected location is external (different domain)
                if location:
                    loc_parsed = urlparse(location)
                    if loc_parsed.netloc and loc_parsed.netloc != parsed.netloc:
                        findings.append({"param": param, "location": location})

        except Exception:
            continue

    duration_ms = int((time.time() - start) * 1000)
    severity = "MEDIUM" if findings else "LOW"

    return {
        "name": "Open Redirect (passive check)",
        "severity": severity,
        "description": (
            f"Found {len(findings)} redirect parameters that may allow external redirects."
            if findings else "No open-redirect parameters detected on common parameter names."
        ),
        "fix": "Validate and restrict redirect parameters to internal paths or use server-side token mapping.",
        "evidence": findings,
        "_meta": {"scan_duration_ms": duration_ms}
    }

def scan(url: str, timeout: int = 10):
    """Alias for compatibility with VulnSight framework"""
    return check_open_redirect(url, timeout=timeout)

def run(url: str, timeout: int = 10):
    """Alias for scan() — called by main backend"""
    return scan(url, timeout=timeout)
