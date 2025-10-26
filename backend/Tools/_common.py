# Tools/_common.py
"""
Common helpers used across Tools modules.
"""

import time
from typing import Tuple, Optional, Dict, Any
import requests
from urllib.parse import urlparse

_USER_AGENT = "VulnSight-Tool/1.0"

def _normalize_url(raw: str) -> str:
    if not raw:
        return raw
    parsed = urlparse(raw)
    if not parsed.scheme:
        raw = "http://" + raw
    return raw

def _safe_get(url: str, timeout: int = 10, allow_redirects: bool = True) -> Tuple[Optional[requests.Response], Optional[str]]:
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=allow_redirects, headers={"User-Agent": _USER_AGENT})
        return resp, None
    except requests.exceptions.RequestException as e:
        return None, str(e)

def _make_base_result(name: str, duration_ms: int = 0) -> Dict[str, Any]:
    return {
        "name": name,
        "severity": "Unknown",
        "description": "",
        "fix": "",
        "references": [],
        "_meta": {"scan_duration_ms": duration_ms}
    }