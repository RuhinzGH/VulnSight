# tools/cors.py

import requests
import time

DEFAULT_CONFIG = {
    "timeout": 5.0,
    "rate_limit_sleep": 0.25,
    "user_agent": "VulnSight/1.0 (passive-cors; authorized use only)",
    "test_origins": ["https://evil.com", "https://attacker.net", "null"]
}


def run(url, config=None):
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    findings = []

    try:
        for origin in cfg["test_origins"]:
            time.sleep(cfg["rate_limit_sleep"])
            headers = {"Origin": origin, "User-Agent": cfg["user_agent"]}

            try:
                resp = requests.get(url, headers=headers, timeout=cfg["timeout"])
                allow_origin = resp.headers.get("Access-Control-Allow-Origin", "")
                allow_creds = resp.headers.get("Access-Control-Allow-Credentials", "false")

                # Determine severity
                if allow_origin == "*" and allow_creds.lower() == "true":
                    severity = "High"
                    likelihood = 90
                    note = "Wildcard origin with credentials allowed — very risky."
                elif allow_origin == "*" or allow_origin == origin:
                    severity = "Medium"
                    likelihood = 65
                    note = "CORS may allow untrusted origins."
                else:
                    severity = "Low"
                    likelihood = 15
                    note = "CORS is properly restricted."

                findings.append({
                    "tested_origin": origin,
                    "allow_origin": allow_origin,
                    "allow_credentials": allow_creds,
                    "severity": severity,
                    "likelihood": f"{likelihood}%",
                    "note": note
                })

            except requests.RequestException as e:
                findings.append({
                    "tested_origin": origin,
                    "error": str(e)
                })

        report = {
            "tool": "cors_misconfiguration",
            "target": url,
            "findings": findings,
            "notes": [
                "Safe, passive scan performed. No data was sent beyond harmless headers.",
                "Use report for guidance; manual verification recommended."
            ]
        }
        return report

    except Exception as e:
        return {
            "tool": "cors_misconfiguration",
            "target": url,
            "findings": [],
            "notes": [f"Scan failed with error: {e}"]
        }
