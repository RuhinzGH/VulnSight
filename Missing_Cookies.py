# tools/insecure_cookies.py

import requests
from http.cookies import SimpleCookie

DEFAULT_CONFIG = {
    "timeout": 5.0,
    "user_agent": "VulnSight/1.0 (passive-cookies; authorized use only)"
}

def run(url, config=None):
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    report = {"tool": "insecure_cookies", "target": url, "findings": [], "notes": []}

    try:
        headers = {"User-Agent": cfg["user_agent"]}
        resp = requests.get(url, headers=headers, timeout=cfg["timeout"])

        set_cookie_headers = resp.headers.getlist("Set-Cookie") if hasattr(resp.headers, "getlist") else [resp.headers.get("Set-Cookie")]
        cookies = [c for c in set_cookie_headers if c]

        if not cookies:
            report["notes"].append("No Set-Cookie headers found; site may not use cookies or is session-less.")
            return report

        total_score = 100  # start perfect, subtract for each missing flag

        for c in cookies:
            cookie = SimpleCookie()
            cookie.load(c)

            for key, morsel in cookie.items():
                flags = {
                    "HttpOnly": bool(morsel["httponly"]),
                    "Secure": bool(morsel["secure"]),
                    "SameSite": morsel["samesite"].capitalize() if morsel["samesite"] else None
                }

                # Determine severity and likelihood
                missing_flags = [k for k, v in flags.items() if not v]
                severity = "Low"
                likelihood = 20
                if missing_flags:
                    severity = "Medium" if len(missing_flags) == 1 else "High"
                    likelihood = 60 if len(missing_flags) == 1 else 90
                    total_score -= len(missing_flags) * 20  # reduce score per missing flag

                report["findings"].append({
                    "cookie_name": key,
                    "domain": morsel["domain"] or "N/A",
                    "path": morsel["path"] or "/",
                    "expires": morsel["expires"] or "Session",
                    "flags": flags,
                    "severity": severity,
                    "likelihood": f"{likelihood}%",
                    "note": f"Missing flags: {', '.join(missing_flags)}" if missing_flags else "All important flags set."
                })

        # Clamp score
        total_score = max(0, total_score)
        report["notes"].append(f"Site-wide cookie security score: {total_score}/100")
        report["notes"].append("Passive scan: no cookies were modified or injected.")
        return report

    except Exception as e:
        return {"tool": "insecure_cookies", "target": url, "findings": [], "notes": [f"Scan failed with error: {e}"]}
