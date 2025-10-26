# tools/outdated_software.py

import requests
from bs4 import BeautifulSoup
import datetime

DEFAULT_CONFIG = {
    "timeout": 5.0,
    "rate_limit_sleep": 0.25,
    "user_agent": "VulnSight/1.0 (passive-software; authorized use only)",
    "known_versions": {
        "WordPress": "6.4",
        "Joomla": "4.4",
        "Drupal": "10.3",
        "PHP": "8.2"
    }
}

def run(url, config=None):
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    findings = []

    try:
        headers = {"User-Agent": cfg["user_agent"]}
        resp = requests.get(url, headers=headers, timeout=cfg["timeout"])
        html = resp.text

        soup = BeautifulSoup(html, "html.parser")

        # --- WordPress detection ---
        wp_generator = soup.find("meta", {"name": "generator"})
        if wp_generator and "WordPress" in wp_generator.get("content", ""):
            version = wp_generator["content"].split(" ")[1] if len(wp_generator["content"].split(" ")) > 1 else "Unknown"
            severity = "Low"
            likelihood = 15
            latest = cfg["known_versions"].get("WordPress")
            if version != "Unknown" and latest and version < latest:
                severity = "Medium"
                likelihood = 65
                note = f"WordPress version {version} detected; latest is {latest}."
            else:
                note = f"WordPress version {version} detected."
            findings.append({
                "software": "WordPress",
                "detected_version": version,
                "severity": severity,
                "likelihood": f"{likelihood}%",
                "note": note
            })

        # --- PHP version from headers ---
        server_header = resp.headers.get("X-Powered-By") or resp.headers.get("Server")
        if server_header:
            for software in cfg["known_versions"]:
                if software.lower() in server_header.lower():
                    version = server_header.split("/")[1] if "/" in server_header else "Unknown"
                    severity = "Low"
                    likelihood = 15
                    latest = cfg["known_versions"].get(software)
                    if version != "Unknown" and latest and version < latest:
                        severity = "Medium"
                        likelihood = 65
                        note = f"{software} version {version} detected; latest is {latest}."
                    else:
                        note = f"{software} version {version} detected."
                    findings.append({
                        "software": software,
                        "detected_version": version,
                        "severity": severity,
                        "likelihood": f"{likelihood}%",
                        "note": note
                    })

        report = {
            "tool": "outdated_software",
            "target": url,
            "findings": findings,
            "notes": [
                "Passive scan: no intrusive actions performed.",
                "Manual verification recommended before mitigation."
            ]
        }

        return report

    except Exception as e:
        return {
            "tool": "outdated_software",
            "target": url,
            "findings": [],
            "notes": [f"Scan failed with error: {e}"]
        }
