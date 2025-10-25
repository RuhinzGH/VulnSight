# Tools/outdates_software.py
"""
Basic outdated software detection using Server and X-Powered-By headers and TLS cert info.
Non-destructive and heuristic-only.

This enhanced version parses common header fingerprints for versions and compares them
to a small local threshold table. It preserves the original return structure but adds
two non-breaking fields:
- found_versions: dict of parsed product -> version string (if found)
- outdated_info: list of dicts with details if any product is below the threshold
"""

from ._common import _normalize_url, _safe_get
import time
import re
from urllib.parse import urlparse

_COMMON_HEADERS = ["server", "x-powered-by"]

# Minimal thresholds for "acceptable" versions (example values)
# Format: product_key -> minimal tuple version considered acceptable
# You should tweak these based on your policy. These are conservative placeholders.
MIN_ACCEPTABLE_VERSIONS = {
    "apache": (2, 4, 50),    # Apache >= 2.4.50
    "nginx": (1, 18, 0),     # nginx >= 1.18.0
    "php": (7, 4, 0),        # PHP >= 7.4.0
    "tomcat": (9, 0, 0),     # Tomcat >= 9.0.0
    "iis": (10, 0, 0),       # IIS >= 10.0.0
}

# regex patterns to extract product and version
_PRODUCT_PATTERNS = [
    (re.compile(r"apache/?\s*\/?\s*([0-9]+(?:\.[0-9]+){0,2})", re.I), "apache"),
    (re.compile(r"nginx\/([0-9]+(?:\.[0-9]+){0,2})", re.I), "nginx"),
    (re.compile(r"php\/([0-9]+(?:\.[0-9]+){0,2})", re.I), "php"),
    (re.compile(r"tomcat\/([0-9]+(?:\.[0-9]+){0,2})", re.I), "tomcat"),
    (re.compile(r"microsoft-iis\/([0-9]+(?:\.[0-9]+){0,2})", re.I), "iis"),
    # fallback: try to capture generic "Product/x.y.z"
    (re.compile(r"([A-Za-z\-]+)\/([0-9]+(?:\.[0-9]+){0,2})", re.I), None),
]

def _parse_version_tuple(ver_str: str):
    """Parse '1.2.3' -> (1,2,3). Compare digit-by-digit."""
    parts = re.findall(r"\d+", ver_str)
    if not parts:
        return ()
    return tuple(int(p) for p in parts)

def _is_version_less(v_tuple, threshold_tuple):
    """Compare version tuples digit-by-digit. Missing digits considered 0."""
    maxlen = max(len(v_tuple), len(threshold_tuple))
    for i in range(maxlen):
        a = v_tuple[i] if i < len(v_tuple) else 0
        b = threshold_tuple[i] if i < len(threshold_tuple) else 0
        if a < b:
            return True
        if a > b:
            return False
    return False  # equal

def _extract_products_from_headers(headers: dict):
    """Return mapping product_key -> version_str for recognized headers."""
    found = {}
    for hname in _COMMON_HEADERS:
        val = headers.get(hname)
        if not val:
            continue
        text = val
        # try patterns
        for patt, product_key in _PRODUCT_PATTERNS:
            m = patt.search(text)
            if m:
                if product_key:
                    ver = m.group(1)
                    found[product_key] = ver
                    break
                else:
                    # generic capture fallback
                    name = m.group(1).lower().replace(" ", "-")
                    ver = m.group(2)
                    found[name] = ver
                    break
    return found

def check_outdated_software(url: str, timeout: int = 10):
    start = time.time()
    url = _normalize_url(url)
    resp, err = _safe_get(url, timeout=timeout)
    if err:
        return {"error": "Request failed", "details": err}
    headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    found = {h: headers.get(h) for h in _COMMON_HEADERS if headers.get(h)}
    duration_ms = int((time.time() - start) * 1000)

    # parse versions from headers
    found_versions = _extract_products_from_headers(headers)

    outdated_info = []
    # check against thresholds
    for product, ver_str in found_versions.items():
        parsed = _parse_version_tuple(ver_str)
        threshold = MIN_ACCEPTABLE_VERSIONS.get(product)
        if threshold:
            if _is_version_less(parsed, threshold):
                outdated_info.append({
                    "product": product,
                    "version": ver_str,
                    "threshold": ".".join(str(x) for x in threshold),
                    "message": f"{product} {ver_str} is below threshold {'.'.join(str(x) for x in threshold)}"
                })

    # Decide severity:
    # - HIGH if outdated_info found
    # - MEDIUM if headers found but no outdated detection
    # - LOW if no fingerprint headers
    if outdated_info:
        severity = "HIGH"
        description = f"Outdated software detected: {len(outdated_info)} products. Fingerprint headers: {found}"
    elif found:
        severity = "MEDIUM"
        description = f"Fingerprint headers found: {found}"
    else:
        severity = "LOW"
        description = "No obvious server fingerprint headers returned."

    return {
        "name": "Outdated Software (heuristic)",
        "severity": severity,
        "description": description,
        "fix": "Keep server and frameworks up to date; remove verbose Server/X-Powered-By headers.",
        "response_headers": headers,
        "status_code": resp.status_code,
        "found_versions": found_versions,    # non-breaking extra field
        "outdated_info": outdated_info,      # non-breaking extra field
        "_meta": {"scan_duration_ms": duration_ms}
    }

def scan(url: str, timeout: int = 10):
    return check_outdated_software(url, timeout=timeout)

def run(url: str, timeout: int = 10):
    return scan(url, timeout=timeout)
