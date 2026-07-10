#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAF/CDN fingerprinting helpers."""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple


def _lower_headers(headers) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


HEADER_RULES: Tuple[Tuple[str, str, str], ...] = (
    ("cloudflare", "high", "cf-ray"),
    ("cloudflare", "high", "cf-cache-status"),
    ("akamai", "medium", "x-akamai-"),
    ("aws_cloudfront", "medium", "x-amz-cf-"),
    ("aws_cloudfront", "medium", "via"),
    ("fastly", "medium", "x-fastly-"),
    ("sucuri", "medium", "x-sucuri-"),
    ("incapsula_imperva", "medium", "x-cdn"),
    ("f5_bigip", "medium", "x-wa-info"),
    ("azure_front_door", "medium", "x-azure-ref"),
    ("nginx_app_protect", "low", "server"),
)

BODY_RULES: Tuple[Tuple[str, str, str], ...] = (
    ("modsecurity", "high", "modsecurity"),
    ("modsecurity", "high", "mod_security"),
    ("cloudflare", "medium", "cloudflare ray id"),
    ("sucuri", "medium", "sucuri website firewall"),
    ("imperva", "medium", "incapsula"),
    ("f5_bigip", "high", "the requested url was rejected"),
    ("aws_waf", "medium", "request blocked"),
)


def fingerprint_waf(
    baseline_status: Optional[int],
    baseline_headers,
    baseline_body: str,
    probe_status: Optional[int],
    probe_headers,
    probe_body: str,
) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()

    for label, severity, marker in HEADER_RULES:
        for headers in (_lower_headers(baseline_headers), _lower_headers(probe_headers)):
            for key, value in headers.items():
                target = key if marker.endswith("-") else f"{key}:{value}".lower()
                hay = key if marker.endswith("-") else value.lower()
                if marker.endswith("-"):
                    match = key.startswith(marker)
                elif marker == "via":
                    match = marker in value.lower() and "cloudfront" in value.lower()
                elif marker == "server":
                    match = "app-protect" in value.lower() or "big-ip" in value.lower()
                else:
                    match = marker in target or marker in hay
                if match:
                    sig = (label, "header", key)
                    if sig not in seen:
                        seen.add(sig)
                        findings.append({
                            "vendor": label,
                            "severity": severity,
                            "signal": "header",
                            "detail": f"{key}: {value}",
                        })

    for label, severity, marker in BODY_RULES:
        for body in ((baseline_body or "").lower(), (probe_body or "").lower()):
            if marker in body:
                sig = (label, "body", marker)
                if sig not in seen:
                    seen.add(sig)
                    findings.append({
                        "vendor": label,
                        "severity": severity,
                        "signal": "body",
                        "detail": marker,
                    })

    if probe_status in (403, 406, 429, 501) and baseline_status not in (403, 406, 429, 501):
        sig = ("generic_waf", "status", str(probe_status))
        if sig not in seen:
            seen.add(sig)
            findings.append({
                "vendor": "generic_waf",
                "severity": "medium",
                "signal": "status_block",
                "detail": f"Malicious probe blocked with HTTP {probe_status}",
            })

    return findings
