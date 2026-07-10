#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "n8n CVE-2026-21858 + CVE-2025-68613 detection",
        "description": (
            "Detects n8n instances with version < 1.121 potentially affected by CVE-2026-21858 "
            "and CVE-2025-68613 (arbitrary file read, token forgery, workflow RCE chain)."
        ),
        "author": ["Chocapikk", "KittySploit Team"],
        "severity": "high",
        "cve": ["CVE-2026-21858", "CVE-2025-68613"],
        "references": [
            "https://github.com/Chocapikk/CVE-2026-21858",
        ],
        "modules": [
            "exploits/linux/http/n8n_full_chain_rce",
        ],
        "tags": ["web", "scanner", "n8n", "lfi", "jwt", "rce", "full-chain"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_read", "from_detail": "lfi_path"},
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/linux/http/n8n_full_chain_rce",
                ],
            },
        },
    }

    port = OptPort(5678, "Target port (n8n default)", True)
    ssl = OptBool(False, "SSL enabled: true/false", True, advanced=True)

    @staticmethod
    def _version_tuple(value: str):
        parts = []
        for part in str(value or "").split("."):
            digits = "".join(ch for ch in part if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _is_vulnerable(self, version: str) -> bool:
        major, minor, _patch = self._version_tuple(version)
        return major < 1 or (major == 1 and minor < 121)

    def run(self):
        try:
            settings = self.http_request(
                method="GET",
                path="/rest/settings",
                timeout=max(int(self.timeout or 10), 10),
                allow_redirects=True,
            )
            if not settings or settings.status_code != 200:
                return False

            data, err = parse_json_response(settings)
            if err or not data:
                return False

            version = str((data.get("data") or {}).get("versionCli", "")).strip()
            if not version or version == "0.0.0":
                return False

            if not self._is_vulnerable(version):
                self.set_info(
                    severity="info",
                    reason=f"n8n {version} detected; appears patched (>= 1.121)",
                    version=version,
                )
                return False

            self.set_info(
                severity="high",
                cve="CVE-2026-21858",
                reason=(
                    f"n8n {version} detected in vulnerable range (< 1.121) for "
                    "CVE-2026-21858 / CVE-2025-68613"
                ),
                version=version,
                confidence="high",
            )
            return True
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
