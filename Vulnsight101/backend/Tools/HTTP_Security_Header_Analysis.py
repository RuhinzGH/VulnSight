# Tools/HTTP_Security_Headers_Check.py
"""
Analyzes security-related HTTP headers in a web response.
Grades site based on the presence of recommended security headers.
Non-intrusive; only performs a GET request.
"""

from ._common import _normalize_url, _safe_get
import time

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Forces HTTPS connections, preventing downgrade attacks.",
        "weight": 2,
        "severity": "HIGH"
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME type sniffing; protects against content-type attacks.",
        "weight": 1,
        "severity": "MEDIUM"
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking by controlling iframe embedding.",
        "weight": 2,
        "severity": "HIGH"
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter in some browsers (not very relevant now).",
        "weight": 1,
        "severity": "LOW"
    },
    "Content-Security-Policy": {
        "desc": "Controls which resources/scripts can be loaded/executed.",
        "weight": 3,
        "severity": "HIGH"
    },
    "Referrer-Policy": {
        "desc": "Controls what referrer information is sent to other sites.",
        "weight": 1,
        "severity": "LOW"
    },
    "Permissions-Policy": {
        "desc": "Controls browser features like camera, microphone, geolocation.",
        "weight": 2,
        "severity": "MEDIUM"
    }
}

def _grade_score(score, max_score):
    percent = (score / max_score) * 100 if max_score else 0
    if percent >= 90:
        return "A"
    elif percent >= 75:
        return "B"
    elif percent >= 60:
        return "C"
    elif percent >= 40:
        return "D"
    else:
        return "F"

def check_security_headers(url: str, timeout: int = 10):
    start = time.time()
    url = _normalize_url(url)
    resp, err = _safe_get(url, timeout=timeout)
    if err:
        return {"error": "Request failed", "details": err}

    headers = resp.headers
    total_weight = sum(v["weight"] for v in SECURITY_HEADERS.values())
    score = 0
    header_results = {}

    for name, info in SECURITY_HEADERS.items():
        if name in headers:
            header_results[name] = {
                "present": True,
                "description": info["desc"],
                "severity": "SAFE"
            }
            score += info["weight"]
        else:
            header_results[name] = {
                "present": False,
                "description": info["desc"],
                "severity": info["severity"]
            }

    grade = _grade_score(score, total_weight)
    duration_ms = int((time.time() - start) * 1000)

    return {
        "name": "HTTP Security Headers",
        "severity": "HIGH" if grade in ["D", "F"] else "MEDIUM" if grade == "C" else "LOW",
        "description": f"Detected {score}/{total_weight} recommended headers. Overall grade: {grade}.",
        "fix": "Add or configure missing HTTP security headers like HSTS, CSP, and X-Frame-Options.",
        "references": ["https://owasp.org/www-project-secure-headers/"],
        "headers": header_results,
        "score": score,
        "grade": grade,
        "_meta": {"scan_duration_ms": duration_ms}
    }

def run(url: str, timeout: int = 10):
    return check_security_headers(url, timeout=timeout)

def scan(url: str, timeout: int = 10):
    return run(url, timeout=timeout)
