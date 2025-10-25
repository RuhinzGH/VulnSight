# tools/ssl_tls_check.py

import ssl
import socket
import datetime

DEFAULT_CONFIG = {
    "port": 443,
    "timeout": 5.0
}

def run(hostname, config=None):
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    report = {
        "tool": "ssl_tls_check",
        "target": hostname,
        "findings": [],
        "notes": []
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, cfg["port"]), timeout=cfg["timeout"]) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Extract key fields
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        now = datetime.datetime.utcnow()

        # Determine severity
        if now > not_after:
            severity = "High"
            likelihood = 95
            note = "Certificate has expired."
        elif (not_after - now).days <= 30:
            severity = "Medium"
            likelihood = 70
            note = f"Certificate will expire soon ({(not_after - now).days} days)."
        else:
            severity = "Low"
            likelihood = 10
            note = "Certificate is valid."

        report["findings"].append({
            "subject_common_name": subject.get("commonName"),
            "issuer_common_name": issuer.get("commonName"),
            "valid_from": cert["notBefore"],
            "valid_to": cert["notAfter"],
            "severity": severity,
            "likelihood": f"{likelihood}%",
            "note": note
        })

        # Add metadata
        report["notes"].append("SSL/TLS certificate read-only check completed. No intrusive actions performed.")
        return report

    except Exception as e:
        return {
            "tool": "ssl_tls_check",
            "target": hostname,
            "findings": [],
            "notes": [f"Scan failed with error: {e}"]
        }
