# Tools/Sensitive_Info_Disclosure.py
"""
Passive check for common sensitive files (robots.txt, /.env, /.git/config, /config.php, etc.).
Non-destructive: only GETs and looks for tell-tale strings. Does NOT attempt to exfiltrate secrets.
"""

from ._common import _normalize_url, _safe_get
import time

# Expanded list of files commonly exposing sensitive data
_CANDIDATE_PATHS = [
    "/robots.txt",
    "/.env",
    "/.git/config",
    "/config.php",
    "/.aws/credentials",
    "/.DS_Store",
    "/backup.zip",
    "/db_backup.sql",
    "/wp-config.php",
    "/config.json",
    "/credentials.txt"
]

# Keyword patterns often found in leaked configs or secret files
_SIGNATURES = [
    "DB_PASSWORD",
    "AWS_ACCESS_KEY_ID",
    "root:x:",
    "PRIVATE_KEY",
    "BEGIN RSA PRIVATE KEY",
    "<configuration>",
    "SECRET_KEY",
    "password=",
    "Authorization:",
    "token="
]

# File-based severity weighting
_SEVERITY_MAP = {
    ".env": "HIGH",
    ".git/config": "HIGH",
    "config.php": "HIGH",
    ".aws/credentials": "HIGH",
    "wp-config.php": "HIGH",
    "db_backup.sql": "HIGH",
    "config.json": "MEDIUM",
    "backup.zip": "MEDIUM",
    "robots.txt": "LOW",
    ".DS_Store": "LOW",
    "credentials.txt": "MEDIUM"
}


def check_sensitive_info(url: str, timeout: int = 10):
    start = time.time()
    url = _normalize_url(url)
    findings = []
    max_severity = "LOW"

    for p in _CANDIDATE_PATHS:
        probe = url.rstrip("/") + p
        resp, err = _safe_get(probe, timeout=timeout)
        if resp and resp.status_code == 200 and resp.text:
            text = resp.text
            for sig in _SIGNATURES:
                if sig.lower() in text.lower():
                    # determine severity based on file type
                    file_severity = _SEVERITY_MAP.get(p.strip("/"), "MEDIUM")
                    findings.append({
                        "path": probe,
                        "signature": sig,
                        "severity": file_severity
                    })

                    # escalate global severity if a high-risk file found
                    if file_severity == "HIGH":
                        max_severity = "HIGH"
                    elif file_severity == "MEDIUM" and max_severity != "HIGH":
                        max_severity = "MEDIUM"

    duration_ms = int((time.time() - start) * 1000)

    return {
        "name": "Sensitive Info Disclosure (passive)",
        "severity": max_severity if findings else "LOW",
        "description": (
            f"Found {len(findings)} candidate disclosures across sensitive paths."
            if findings else
            "No obvious sensitive file contents found on common paths."
        ),
        "fix": "Ensure sensitive files are not served publicly and secrets are stored in secure vaults.",
        "evidence": findings,
        "_meta": {"scan_duration_ms": duration_ms}
    }


def scan(url: str, timeout: int = 10):
    return check_sensitive_info(url, timeout=timeout)


def run(url: str, timeout: int = 10):
    return scan(url, timeout=timeout)
