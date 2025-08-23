# tools/xss.py

import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

DEFAULT_CONFIG = {
    "timeout": 5.0,
    "rate_limit_sleep": 0.25,
    "user_agent": "VulnSight/1.0 (passive-xss; authorized use only)",
    "marker": "__VS_XSS_TEST__"
}

def _inject_param(url, param, value):
    p = urlparse(url)
    q = parse_qs(p.query)
    q[param] = value
    new_q = urlencode(q, doseq=True)
    return urlunparse(p._replace(query=new_q))

def run(target_url, config=None):
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    report = {"tool": "xss_reflection", "target": target_url, "findings": [], "notes": []}

    try:
        parsed = urlparse(target_url)
        params = parse_qs(parsed.query)

        if not params:
            report["notes"].append("No query parameters found; only baseline checks performed.")
            return report

        for param in params:
            probe_url = _inject_param(target_url, param, cfg["marker"])
            time.sleep(cfg["rate_limit_sleep"])
            try:
                resp = requests.get(probe_url, headers={"User-Agent": cfg["user_agent"]}, timeout=cfg["timeout"])
                body = resp.text

                if cfg["marker"] in body:
                    severity = "Medium"
                    likelihood = 80
                    note = "Marker reflected in page; potential XSS risk if scripts are injected."
                elif any(escaped in body for escaped in ["&lt;", "&gt;", "&quot;", "&#x"]):
                    severity = "Low"
                    likelihood = 40
                    note = "Marker partially escaped; site partially sanitizes input."
                else:
                    severity = "None"
                    likelihood = 0
                    note = "No reflection detected."

                report["findings"].append({
                    "param": param,
                    "tested_value": cfg["marker"],
                    "severity": severity,
                    "likelihood": f"{likelihood}%",
                    "note": note
                })

            except requests.RequestException as e:
                report["findings"].append({
                    "param": param,
                    "error": str(e)
                })

        report["notes"].append("Safe passive scan; no scripts were executed. Manual verification recommended.")
        return report

    except Exception as e:
        return {"tool": "xss_reflection", "target": target_url, "findings": [], "notes": [f"Scan failed with error: {e}"]}
