# Tools/PathTraversal.py
"""
Dynamic, safe Path Traversal tester for VulnSight.

Now with:
- File-type → severity mapping for each evidence
- Shared _common helpers for consistency
- Safe, non-destructive GET requests only
- Fully compatible return format
"""

import re
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from typing import Dict, Any, List, Optional
from ._common import _normalize_url, _safe_get  # ✅ using shared helpers

# -----------------------------
# Config: payloads and signatures
# -----------------------------
BASIC_PAYLOADS = [
    "../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\boot.ini"
]

ENCODED_PAYLOADS = [
    ("%2e%2e%2f" * n) for n in range(1, 6)
] + [
    ("%2e%2e%5c" * n) for n in range(1, 6)
]

SIGNATURES = {
    "etc_passwd": re.compile(r"root:.*:0:0:", re.IGNORECASE),
    "win_ini": re.compile(r"\[fonts\]|\[extensions\]|\[boot\]", re.IGNORECASE),
    "apache_index": re.compile(r"Index of /", re.IGNORECASE)
}

SIGNATURE_SEVERITY = {
    "etc_passwd": "HIGH",
    "win_ini": "HIGH",
    "apache_index": "MEDIUM"
}

# -----------------------------
# Helper to match file signatures
# -----------------------------
def match_signatures(text: Optional[str]) -> List[str]:
    found: List[str] = []
    if not text:
        return found
    for name, pattern in SIGNATURES.items():
        try:
            if pattern.search(text):
                found.append(name)
        except Exception:
            continue
    return found

# -----------------------------
# Main scan function
# -----------------------------
def scan(url: str, timeout: int = 10) -> Dict[str, Any]:
    start_ts = time.time()
    url = _normalize_url(url)
    parsed = urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    results: Dict[str, Any] = {
        "vulnerability": "Path Traversal",
        "status": "ok",
        "severity": "LOW",
        "details": {"probes": [], "evidence": []},
        "_meta": {}
    }

    # Detect likely parameters
    params = parse_qs(parsed.query)
    common_params = ["file", "filename", "path", "filepath", "download", "doc", "url", "view"]
    test_params = [p for p in params.keys() if p.lower() in common_params]
    if not test_params:
        test_params = common_params[:2]

    payloads = BASIC_PAYLOADS + ENCODED_PAYLOADS

    # -----------------------------
    # Path-based payload tests
    # -----------------------------
    for p in payloads:
        base_path = parsed.path if parsed.path else "/"
        if not base_path.endswith("/"):
            base_path = base_path.rsplit("/", 1)[0] + "/"
        probe_url = urljoin(base_origin + base_path, p)

        resp, err = _safe_get(probe_url, timeout=timeout)
        text = resp.text if resp and getattr(resp, "text", None) else ""
        sigs = match_signatures(text)
        results["details"]["probes"].append({
            "type": "path",
            "payload": p,
            "url": probe_url,
            "status": getattr(resp, "status_code", None),
            "error": err,
            "signatures": sigs
        })
        for sig in sigs:
            severity_hint = SIGNATURE_SEVERITY.get(sig, "LOW")
            results["details"]["evidence"].append({
                "payload": p,
                "url": probe_url,
                "signatures": [sig],
                "severity_hint": severity_hint
            })

    # -----------------------------
    # Parameter-based payload tests
    # -----------------------------
    for param in test_params:
        for p in payloads[:6]:
            connector = "&" if "?" in url else "?"
            probe_url = url + connector + urlencode({param: p})
            resp, err = _safe_get(probe_url, timeout=timeout)
            text = resp.text if resp and getattr(resp, "text", None) else ""
            sigs = match_signatures(text)
            results["details"]["probes"].append({
                "type": "param",
                "param": param,
                "payload": p,
                "url": probe_url,
                "status": getattr(resp, "status_code", None),
                "error": err,
                "signatures": sigs
            })
            for sig in sigs:
                severity_hint = SIGNATURE_SEVERITY.get(sig, "LOW")
                results["details"]["evidence"].append({
                    "param": param,
                    "payload": p,
                    "url": probe_url,
                    "signatures": [sig],
                    "severity_hint": severity_hint
                })

    # -----------------------------
    # Determine overall severity
    # -----------------------------
    evidence = results["details"]["evidence"]
    if evidence:
        if any(e.get("severity_hint") == "HIGH" for e in evidence):
            results["severity"] = "HIGH"
        elif any(e.get("severity_hint") == "MEDIUM" for e in evidence):
            results["severity"] = "MEDIUM"

    if not results["details"]["probes"]:
        results["status"] = "unknown"
        results["severity"] = "UNKNOWN"

    duration_ms = int((time.time() - start_ts) * 1000)
    results["_meta"]["scan_duration_ms"] = duration_ms
    results["_meta"]["module_callable"] = "scan"

    return results

# -----------------------------
# Compatibility entrypoint
# -----------------------------
def run(url: str, timeout: int = 10) -> Dict[str, Any]:
    return scan(url, timeout=timeout)

# -----------------------------
# CLI test
# -----------------------------
if __name__ == "__main__":
    import json
    u = input("Enter URL to scan: ").strip()
    print(json.dumps(run(u), indent=2))
