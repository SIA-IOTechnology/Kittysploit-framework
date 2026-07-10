#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HSTS and OCSP stapling audit helpers."""

from __future__ import annotations

import re
import shutil
import socket
import ssl
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class HstsAuditResult:
    http_redirects_to_https: bool = False
    https_available: bool = False
    hsts_present: bool = False
    hsts_header: str = ""
    max_age: Optional[int] = None
    include_subdomains: bool = False
    preload: bool = False
    issues: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class OcspAuditResult:
    checked: bool = False
    stapling_present: Optional[bool] = None
    detail: str = ""
    method: str = ""


def parse_hsts_header(value: str) -> Tuple[Optional[int], bool, bool]:
    max_age = None
    include_subdomains = False
    preload = False
    for part in (value or "").split(";"):
        token = part.strip().lower()
        if token.startswith("max-age="):
            try:
                max_age = int(token.split("=", 1)[1].strip())
            except ValueError:
                max_age = None
        elif token == "includesubdomains":
            include_subdomains = True
        elif token == "preload":
            preload = True
    return max_age, include_subdomains, preload


def audit_hsts_from_headers(
    *,
    http_status: Optional[int],
    http_headers: Dict[str, str],
    http_location: str,
    https_status: Optional[int],
    https_headers: Dict[str, str],
    host: str,
) -> HstsAuditResult:
    result = HstsAuditResult()
    http_headers_l = {str(k).lower(): str(v) for k, v in (http_headers or {}).items()}
    https_headers_l = {str(k).lower(): str(v) for k, v in (https_headers or {}).items()}

    if https_status is not None:
        result.https_available = True

    location = (http_location or "").lower()
    if http_status in (301, 302, 307, 308) and location.startswith("https://"):
        result.http_redirects_to_https = True
    elif http_status == 200 and host:
        result.issues.append({
            "type": "no_http_redirect",
            "severity": "medium",
            "description": "HTTP does not redirect to HTTPS",
        })

    hsts = https_headers_l.get("strict-transport-security", "")
    if hsts:
        result.hsts_present = True
        result.hsts_header = hsts
        max_age, include_subdomains, preload = parse_hsts_header(hsts)
        result.max_age = max_age
        result.include_subdomains = include_subdomains
        result.preload = preload
        if max_age is not None and max_age < 15552000:
            result.issues.append({
                "type": "short_hsts_max_age",
                "severity": "low",
                "description": f"HSTS max-age is only {max_age} seconds (< 180 days)",
            })
    else:
        result.issues.append({
            "type": "missing_hsts",
            "severity": "medium",
            "description": "Strict-Transport-Security header missing on HTTPS",
        })

    if http_headers_l.get("strict-transport-security"):
        result.issues.append({
            "type": "hsts_on_http",
            "severity": "low",
            "description": "HSTS header present on cleartext HTTP response",
        })
    return result


def probe_ocsp_stapling(host: str, port: int = 443, server_name: str = "", timeout: float = 8.0) -> OcspAuditResult:
    result = OcspAuditResult()
    sni = (server_name or host).strip()
    openssl = shutil.which("openssl")
    if openssl:
        result.method = "openssl_s_client"
        try:
            proc = subprocess.run(
                [
                    openssl,
                    "s_client",
                    "-connect",
                    f"{host}:{int(port)}",
                    "-servername",
                    sni,
                    "-status",
                    "-brief",
                ],
                input=b"",
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            output = (proc.stdout or b"") + (proc.stderr or b"")
            text = output.decode("utf-8", errors="replace")
            result.checked = True
            if "OCSP response: no response sent" in text or "OCSP Response Status: no response sent" in text:
                result.stapling_present = False
                result.detail = "Server did not send OCSP stapling response"
            elif "OCSP Response Status:" in text:
                result.stapling_present = True
                match = re.search(r"OCSP Response Status:\s*(\w+)", text)
                result.detail = match.group(0) if match else "OCSP response present"
            else:
                result.detail = "Unable to parse OCSP status from openssl output"
        except Exception as exc:
            result.detail = str(exc)
        return result

    # Fallback: TLS connect only — cannot reliably detect stapling without openssl.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni) as tls:
                tls.do_handshake()
                result.checked = True
                result.method = "ssl_handshake"
                result.stapling_present = None
                result.detail = "TLS handshake OK; install openssl for OCSP stapling probe"
    except Exception as exc:
        result.detail = str(exc)
    return result
