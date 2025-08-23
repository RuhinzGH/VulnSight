# tools/openredirect.py

import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

DEFAULT_CONFIG = {
    "timeout": 5.0,
    "rate_limit_sleep": 0.25,
    "user_agent": "VulnSight/1.0 (passive-openredirect; authorized use only)",
    "test_url": "https://vulnsight-test.com"
}


def _inject_param(url, param, value):
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    p = urlparse(url)
    q = parse_qs(p.query)
    q[param] = value
    new_q = urlencode(q, doseq=True)
    return urlunparse(p._replace(query=new_q))


def run(target_url, config=None):
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    report = {"tool": "open_redirect", "target": target_url, "findings": [], "notes": []}

    try:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        if not params:
            report["notes"].append("No URL parameters found; only baseline checks performed.")
            return report

        for param in params:
            test_url = _inject_param(target_url, param, cfg["test_url"])
            time.sleep(cfg["rate_limit_sleep"])
            try:
                resp = requests.get(test_url, headers={"User-Agent": cfg["user_agent"]}, allow_redirects=False,
                                    timeout=cfg["timeout"])
                location = resp.headers.get("Location", "")

                if location == cfg["test_url"]:
                    severity = "High"
                    likelihood = 90
                    note = "Parameter can redirect to arbitrary URL — phishing risk."
                elif location:
                    severity = "Medium"
                    likelihood = 60
                    note = "Parameter redirects but not fully arbitrary — check for whitelisting."
                else:
                    severity = "Low"
                    likelihood = 10
                    note = "Parameter does not allow redirection."

                report["findings"].append({
                    "param": param,
                    "tested_value": cfg["test_url"],
                    "location_header": location,
                    "severity": severity,
                    "likelihood": f"{likelihood}%",
                    "note": note
                })

            except requests.RequestException as e:
                report["findings"].append({
                    "param": param,
                    "error": str(e)
                })

        report["notes"].append("Passive scan: only harmless test URL used. Manual verification recommended.")
        return report

    except Exception as e:
        return {"tool": "open_redirect", "target": target_url, "findings": [],
                "notes": [f"Scan failed with error: {e}"]}
