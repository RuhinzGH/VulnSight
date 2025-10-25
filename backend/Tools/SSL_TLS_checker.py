# Tools/SSL_TLS_checker.py
"""
TLS certificate inspector (drop-in replacement).

Features:
 - Tries TLS handshake with SNI (server_hostname=host) first, then without SNI,
   then falls back to ssl.get_server_certificate + best-effort parsing.
 - Probes individual TLS versions (non-invasive handshake attempts) to report
   supported protocol versions.
 - Produces a compact, human-readable `description` (bulleted / line-separated)
   while preserving detailed `tls_notes` for diagnostics.
 - Keeps return shape compatible with existing tools used by VulnSight.
"""

import ssl
import socket
import time
import tempfile
import os
import ipaddress
from datetime import datetime
from typing import Tuple, List, Optional, Dict
from urllib.parse import urlparse

from ._common import _normalize_url

# Try to import TLSVersion (newer Python) for robust version forcing
try:
    from ssl import TLSVersion  # type: ignore
except Exception:
    TLSVersion = None


def _parse_notafter(notafter_str: str) -> Optional[datetime]:
    if not notafter_str:
        return None
    # Common OpenSSL format: "Apr 12 23:59:59 2026 GMT"
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            return datetime.strptime(notafter_str, fmt)
        except Exception:
            continue
    # Fallback to ISO-like parse
    try:
        return datetime.fromisoformat(notafter_str)
    except Exception:
        return None


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except Exception:
        return False


def _probe_tls_versions(host: str, port: int, timeout: int = 5) -> Tuple[List[str], List[str]]:
    """
    Attempt single-version handshakes to see which versions server negotiates.
    Returns (versions_list, notes_list).
    Best-effort and non-invasive: one handshake per version.
    """
    versions: List[str] = []
    notes: List[str] = []

    checks: List[Tuple[str, Optional[object]]] = []
    if TLSVersion is not None:
        checks = [
            ("TLSv1.3", TLSVersion.TLSv1_3),
            ("TLSv1.2", TLSVersion.TLSv1_2),
            ("TLSv1.1", TLSVersion.TLSv1_1),
            ("TLSv1.0", TLSVersion.TLSv1),
        ]
    else:
        # Older Python/openSSL: best-effort labeled checks
        checks = [("TLSv1.3", None), ("TLSv1.2", None), ("TLSv1.1", None), ("TLSv1.0", None)]

    for label, tv in checks:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            if TLSVersion is not None and tv is not None:
                try:
                    ctx.minimum_version = tv  # type: ignore
                    ctx.maximum_version = tv  # type: ignore
                except Exception:
                    # best-effort, continue on platforms that don't allow forcing min/max
                    pass
            else:
                # fallback heuristics: try to disable newer/older versions where possible
                try:
                    if label == "TLSv1.2":
                        ctx.options |= getattr(ssl, "OP_NO_TLSv1_3", 0)
                        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
                        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
                    elif label == "TLSv1.1":
                        ctx.options |= getattr(ssl, "OP_NO_TLSv1_3", 0)
                        ctx.options |= getattr(ssl, "OP_NO_TLSv1_2", 0)
                        ctx.options |= getattr(ssl, "OP_NO_TLSv1", 0)
                    elif label == "TLSv1.0":
                        ctx.options |= getattr(ssl, "OP_NO_TLSv1_3", 0)
                        ctx.options |= getattr(ssl, "OP_NO_TLSv1_2", 0)
                        ctx.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
                except Exception:
                    pass

            with socket.create_connection((host, port), timeout=timeout) as sock:
                try:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        negotiated = ssock.version()
                        if negotiated:
                            versions.append(negotiated)
                            notes.append(f"{label} probe negotiated as {negotiated}")
                except ssl.SSLError as se:
                    notes.append(f"{label} probe handshake failed: {se}")
                except Exception as e:
                    notes.append(f"{label} probe error: {e}")
        except Exception as e:
            notes.append(f"{label} setup error: {e}")
            continue

    # Deduplicate preserving order
    uniq: List[str] = []
    for v in versions:
        if v and v not in uniq:
            uniq.append(v)
    return uniq, notes


def _attempt_handshake(host: str, port: int, timeout: int, use_sni: bool = True) -> Tuple[Optional[Dict], List[str], Optional[str]]:
    """
    Attempt TLS handshake and return:
      (cert_dict_or_None, notes_list, negotiated_protocol_or_None)
    - use_sni controls server_hostname passed to wrap_socket
    - cert is the dict returned by SSLSocket.getpeercert() where available
    """
    notes: List[str] = []
    cert = None
    negotiated = None

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            try:
                server_hostname = host if use_sni else None
                with ctx.wrap_socket(raw_sock, server_hostname=server_hostname) as ssock:
                    negotiated = ssock.version()
                    # getpeercert often returns a dict; on some platforms it might be {}
                    cert = ssock.getpeercert()
                    notes.append(f"Handshake success (sni={use_sni}) negotiated={negotiated}")
            except ssl.SSLError as se:
                notes.append(f"SSLError during wrap_socket (sni={use_sni}): {se}")
            except Exception as e:
                notes.append(f"Error during TLS handshake (sni={use_sni}): {e}")
    except Exception as e:
        notes.append(f"Connection error to {host}:{port} (sni={use_sni}): {e}")

    return (cert if cert else None), notes, negotiated


def _try_get_server_cert_pem(host: str, port: int, timeout: int = 5) -> Tuple[Optional[str], List[str]]:
    """
    Fallback: ssl.get_server_certificate returns PEM string or raises.
    Return (pem_or_None, notes)
    """
    notes: List[str] = []
    try:
        # ssl.get_server_certificate makes its own socket connection
        pem = ssl.get_server_certificate((host, port), timeout=timeout)
        notes.append("ssl.get_server_certificate succeeded (PEM retrieved)")
        return pem, notes
    except Exception as e:
        notes.append(f"ssl.get_server_certificate failed: {e}")
        return None, notes


def _parse_pem_to_cert_dict(pem: str) -> Tuple[Optional[Dict], List[str]]:
    """
    Best-effort parsing of PEM into dict shape like getpeercert(), using
    ssl._ssl._test_decode_cert by writing PEM to a temporary file.
    Returns (parsed_dict_or_dict_with_pem, notes).
    """
    notes: List[str] = []
    if not pem:
        return None, notes

    tf = None
    try:
        tf = tempfile.NamedTemporaryFile(delete=False)
        tf.write(pem.encode("utf-8"))
        tf.flush()
        tf.close()
        try:
            parsed = ssl._ssl._test_decode_cert(tf.name)  # many CPython builds expose this helper
            notes.append("Parsed PEM via ssl._ssl._test_decode_cert")
            return parsed, notes
        except Exception as e:
            notes.append(f"ssl._ssl._test_decode_cert parse failed: {e}")
            # fallback: return PEM in dict to preserve information
            return {"pem": pem}, notes
    except Exception as e:
        notes.append(f"PEM write/parse failed: {e}")
        return {"pem": pem}, notes
    finally:
        if tf:
            try:
                os.unlink(tf.name)
            except Exception:
                pass


def check_tls(url: str, timeout: int = 10):
    """
    Main entry: returns dictionary compatible with VulnSight tools.
    Contains:
      - name, severity, description, fix
      - cert (dict or {'pem':...})
      - valid_from, valid_to, days_left
      - supported_tls_versions (list), insecure_tls (bool)
      - tls_notes (detailed list of probe/handshake messages)
      - _meta.scan_duration_ms
    """
    start = time.time()
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)

    scheme = (parsed.scheme or "").lower()
    host = parsed.hostname or parsed.path
    if parsed.port:
        port = parsed.port
    else:
        port = 80 if scheme == "http" else 443

    # If explicit plain HTTP and port not 443, skip TLS checks (clear message)
    if scheme == "http" and port != 443:
        duration_ms = int((time.time() - start) * 1000)
        return {
            "name": "SSL/TLS Certificate",
            "severity": "LOW",
            "description": "Target uses plain HTTP (no TLS) — TLS checks skipped.",
            "fix": "Use HTTPS / TLS on the target or point to an https://host:443 endpoint.",
            "cert": None,
            "valid_from": None,
            "valid_to": None,
            "days_left": None,
            "supported_tls_versions": [],
            "insecure_tls": False,
            "tls_notes": ["URL scheme is http and port != 443; TLS handshake not attempted."],
            "_meta": {"scan_duration_ms": duration_ms},
        }

    tls_notes: List[str] = []
    cert = None
    negotiated = None

    # Make timeout a bit more generous for TLS
    timeout = max(timeout, 8)

    try:
        host_is_ip = _is_ip_address(host)
        # 1) Try handshake with SNI unless host is IP (SNI is name-based)
        if not host_is_ip:
            c, notes, negotiated = _attempt_handshake(host, port, timeout, use_sni=True)
            tls_notes.extend(notes or [])
            if c:
                cert = c

        # 2) Try handshake without SNI (some IP-based endpoints or misconfigured hosts)
        if not cert:
            c2, notes2, negotiated2 = _attempt_handshake(host, port, timeout, use_sni=False)
            tls_notes.extend(notes2 or [])
            if c2:
                cert = c2
                negotiated = negotiated2

        # 3) Fallback to ssl.get_server_certificate (PEM) and attempt parse
        if not cert:
            pem, pem_notes = _try_get_server_cert_pem(host, port, timeout=min(6, timeout))
            tls_notes.extend(pem_notes or [])
            if pem:
                parsed_cert, parse_notes = _parse_pem_to_cert_dict(pem)
                tls_notes.extend(parse_notes or [])
                if parsed_cert:
                    cert = parsed_cert

        duration_ms = int((time.time() - start) * 1000)

        # If still no cert, probe supported TLS versions to give diagnostic info
        if not cert:
            tls_probed_versions, probe_notes = _probe_tls_versions(host, port, timeout=min(5, timeout))
            tls_notes.extend(probe_notes or [])
            return {
                "name": "SSL/TLS Certificate",
                "severity": "MEDIUM",
                "description": "Could not retrieve certificate via standard handshake. See tls_notes for diagnostic details.",
                "fix": "Ensure the host accepts TLS connections on the expected port and supports SNI if endpoint is name-based.",
                "cert": None,
                "valid_from": None,
                "valid_to": None,
                "days_left": None,
                "supported_tls_versions": tls_probed_versions,
                "insecure_tls": any(("1.0" in v or "1.1" in v) for v in (tls_probed_versions or [])),
                "tls_notes": tls_notes,
                "_meta": {"scan_duration_ms": duration_ms},
            }

        # We have a cert (dict or dict-with-pem). Extract fields safely.
        subject = {}
        issuer = {}
        try:
            subj = cert.get("subject", ())
            for item in subj:
                if isinstance(item, (list, tuple)) and len(item) > 0 and isinstance(item[0], (list, tuple)):
                    for kv in item:
                        if len(kv) >= 2:
                            subject[kv[0]] = kv[1]
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    subject[item[0]] = item[1]
        except Exception:
            subject = {}

        try:
            iss = cert.get("issuer", ())
            for item in iss:
                if isinstance(item, (list, tuple)) and len(item) > 0 and isinstance(item[0], (list, tuple)):
                    for kv in item:
                        if len(kv) >= 2:
                            issuer[kv[0]] = kv[1]
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    issuer[item[0]] = item[1]
        except Exception:
            issuer = {}

        san = cert.get("subjectAltName", ())
        not_after_raw = cert.get("notAfter") or cert.get("not_after")
        not_before_raw = cert.get("notBefore") or cert.get("not_before")
        valid_to = _parse_notafter(not_after_raw)
        valid_from = _parse_notafter(not_before_raw)
        now = datetime.utcnow()
        days_left = None
        if valid_to:
            days_left = (valid_to - now).days

        severity = "LOW"
        notes_list: List[str] = []

        # Expiry checks
        if valid_to is None:
            severity = "MEDIUM"
            notes_list.append("Could not parse certificate expiry (notAfter missing/unparseable).")
        else:
            if days_left < 0:
                severity = "HIGH"
                notes_list.append(f"Certificate expired {abs(days_left)} day(s) ago.")
            elif days_left <= 7:
                severity = "HIGH"
                notes_list.append(f"Certificate expires in {days_left} day(s).")
            elif days_left <= 30:
                if severity != "HIGH":
                    severity = "MEDIUM"
                notes_list.append(f"Certificate will expire in {days_left} day(s).")
            else:
                notes_list.append(f"Certificate valid for {days_left} more day(s).")

        # Hostname / SAN check (best-effort)
        try:
            host_to_check = (host or "").lower()
            san_names = [v.lower() for t, v in san if t.lower() == "dns"] if san else []
            host_matched = False
            if san_names:
                for name in san_names:
                    if name.startswith("*."):
                        if host_to_check.endswith(name[1:]):
                            host_matched = True
                            break
                    elif host_to_check == name:
                        host_matched = True
                        break
            else:
                cn = subject.get("commonName", "").lower()
                if cn and (cn == host_to_check or (cn.startswith("*.") and host_to_check.endswith(cn[1:]))):
                    host_matched = True

            if not host_matched:
                severity = "MEDIUM" if severity != "HIGH" else severity
                notes_list.append("Hostname does not match certificate subject / SAN.")
            else:
                notes_list.append("Hostname matches certificate subject/SAN.")
        except Exception:
            notes_list.append("Could not determine hostname vs SAN match.")

        # Self-signed detection (issuer == subject)
        try:
            raw_subject = cert.get("subject")
            raw_issuer = cert.get("issuer")
            if raw_subject and raw_issuer and raw_subject == raw_issuer:
                severity = "MEDIUM" if severity != "HIGH" else severity
                notes_list.append("Certificate appears to be self-signed (issuer == subject).")
        except Exception:
            pass

        # Lightweight TLS probing for notes and supported list
        tls_versions, probe_notes = _probe_tls_versions(host, port, timeout=min(5, timeout))
        tls_notes.extend(probe_notes or [])
        supported_norm = list(dict.fromkeys([s for s in (tls_versions or []) if isinstance(s, str)]))

        insecure_tls = False
        for s in supported_norm:
            if "1.0" in s or "1.1" in s or (s.lower().startswith("tlsv1") and ("1.0" in s or "1.1" in s)):
                insecure_tls = True
                break

        if insecure_tls:
            severity = "HIGH"
            tls_notes.append("Server accepts obsolete TLS versions (TLS 1.0 or 1.1) — consider disabling them.")
        else:
            if any("1.3" in s for s in supported_norm):
                tls_notes.append("Server supports TLS 1.3.")
            elif any("1.2" in s for s in supported_norm):
                if severity != "HIGH":
                    severity = "MEDIUM"
                tls_notes.append("Server supports TLS 1.2 (upgrade to 1.3 recommended).")
            else:
                tls_notes.append("Could not determine server TLS versions or no TLS support detected.")

        # Build a concise, human-friendly description (multi-line, readable)
        human_lines: List[str] = []
        # certificate validity
        if valid_to:
            if days_left < 0:
                human_lines.append(f"• Certificate expired {abs(days_left)} day(s) ago.")
            else:
                human_lines.append(f"• Valid for {days_left} more day(s).")
        else:
            human_lines.append("• Certificate expiry could not be determined.")

        # hostname match
        human_lines.append("• Hostname matches certificate." if "Hostname matches certificate subject/SAN." in notes_list else "• Hostname does NOT match certificate.")

        # TLS support summary
        if supported_norm:
            human_lines.append("• Supported TLS: " + ", ".join(supported_norm))
        else:
            human_lines.append("• Supported TLS versions: unknown")

        # self-signed
        self_signed_flag = any("self-signed" in (n or "").lower() for n in (tls_notes + notes_list))
        human_lines.append("• Self-signed: Yes" if self_signed_flag else "• Self-signed: No")

        # overall risk phrase
        human_lines.append(f"• Overall risk: {severity}")

        description = "\n".join(human_lines)

        duration_ms = int((time.time() - start) * 1000)

        return {
            "name": "SSL/TLS Certificate",
            "severity": severity,
            "description": description or "Certificate and TLS protocol inspected.",
            "fix": "Ensure certificate chain is valid, hostname matches, certificate is not self-signed, rotate before expiry, and disable TLS <= 1.1 (prefer TLS 1.3).",
            "cert": cert,
            "valid_from": valid_from.isoformat() if valid_from else None,
            "valid_to": valid_to.isoformat() if valid_to else None,
            "days_left": days_left,
            "supported_tls_versions": supported_norm,
            "insecure_tls": insecure_tls,
            "tls_notes": tls_notes,
            "_meta": {"scan_duration_ms": duration_ms},
        }

    except Exception as e:
        duration_ms = int((time.time() - start) * 1000)
        return {"error": "TLS check failed", "details": str(e), "_meta": {"scan_duration_ms": duration_ms}}


def scan(url: str, timeout: int = 10):
    return check_tls(url, timeout=timeout)


def run(url: str, timeout: int = 10):
    return scan(url, timeout=timeout)
