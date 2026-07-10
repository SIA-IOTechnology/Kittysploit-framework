#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "MindsDB CVE-2026-27483 detection",
        "description": (
            "Detects MindsDB versions < 25.9.1.1 potentially affected by CVE-2026-27483 "
            "(path traversal in /api/files that can lead to RCE)."
        ),
        "author": ["XlabAITeam", "Lohitya Pushkar (thewhiteh4t)", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-27483",
        "references": [
            "https://github.com/mindsdb/mindsdb/security/advisories/GHSA-4894-xqv6-vrfq",
            "https://github.com/mindsdb/mindsdb",
        ],
        "modules": [
            "exploits/linux/http/mindsdb_cve_2026_27483_path_traversal_rce",
        ],
        "tags": ["web", "scanner", "mindsdb", "path-traversal", "cve-2026-27483"],
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
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/linux/http/mindsdb_cve_2026_27483_path_traversal_rce",
                ],
            },
        },
    }

    port = OptPort(47334, "Target port (MindsDB default)", True)
    ssl = OptBool(False, "SSL enabled: true/false", True, advanced=True)
    base_path = OptString("/", "MindsDB base path", required=False)

    def _prefix(self) -> str:
        bp = str(self.base_path or "/").strip()
        if not bp.startswith("/"):
            bp = "/" + bp
        return bp.rstrip("/")

    @staticmethod
    def _parse_version(version_text: str):
        match = re.match(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", str(version_text or "").strip())
        if not match:
            return ()
        return tuple(int(part) for part in match.groups())

    def run(self):
        try:
            status = self.http_request(
                method="GET",
                path=f"{self._prefix()}/api/status",
                timeout=max(int(self.timeout or 10), 10),
            )
            if not status or status.status_code != 200:
                return False

            status_json, err = parse_json_response(status)
            if err or not status_json:
                return False

            version_text = str(status_json.get("mindsdb_version", "")).strip()
            version = self._parse_version(version_text)
            if not version:
                return False

            if version >= (25, 9, 1, 1):
                self.set_info(
                    severity="info",
                    reason=f"MindsDB {version_text} detected; appears patched (>= 25.9.1.1)",
                    version=version_text,
                )
                return False

            auth_enabled = bool((status_json.get("auth") or {}).get("http_auth_enabled"))
            severity = "high" if not auth_enabled else "medium"
            self.set_info(
                severity=severity,
                cve="CVE-2026-27483",
                reason=(
                    f"MindsDB {version_text} detected in vulnerable range (< 25.9.1.1); "
                    f"http_auth_enabled={auth_enabled}"
                ),
                version=version_text,
                confidence="high",
            )
            return True
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
