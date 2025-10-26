# Tools/Directory_Listing_Check.py
"""
Checks for directory listing patterns on common paths.
Non-destructive: only performs safe GET requests.
"""

import time
import re
from ._common import _normalize_url, _safe_get

# Commonly exposed directories where listings are often left open
_COMMON_PATHS = ["/", "/uploads/", "/images/", "/files/", "/assets/"]

def check_dir_listing(url: str, timeout: int = 10):
    start = time.time()
    url = _normalize_url(url)
    findings = []

    for path in _COMMON_PATHS:
        probe_url = url.rstrip("/") + path
        resp, err = _safe_get(probe_url, timeout=timeout)
        
        if resp and resp.status_code == 200 and resp.text:
            html_lower = resp.text.lower()
            # Look for signs of auto-generated directory listings
            if "index of /" in html_lower or re.search(r"<title>\s*index of", html_lower):
                findings.append({
                    "path": probe_url,
                    "snippet": resp.text[:400]
                })

    # Decide severity based on whether we found open directories
    severity = "HIGH" if findings else "LOW"
    description = (
        f"Found {len(findings)} directory listing pages."
        if findings else
        "No directory listings detected on common paths."
    )

    duration_ms = int((time.time() - start) * 1000)
    return {
        "name": "Directory Listing",
        "severity": severity,
        "description": description,
        "fix": "Disable directory listing in server configuration and provide index files for all directories.",
        "references": ["https://owasp.org/www-community/attacks/Directory_listing"],
        "evidence": findings,
        "status_code": 200 if findings else None,
        "text_snippet": (findings[0]["snippet"] if findings else ""),
        "_meta": {"scan_duration_ms": duration_ms, "module_callable": "check_dir_listing"}
    }


def scan(url: str, timeout: int = 10):
    """Wrapper for compatibility"""
    return check_dir_listing(url, timeout=timeout)


def run(url: str, timeout: int = 10):
    """Alias used by async runners"""
    return scan(url, timeout=timeout)
