#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "MindsDB CVE-2026-27483 detection",
        "description": (
            "Detects MindsDB instances potentially vulnerable to CVE-2026-27483 "
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
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
    },
    }

    port = OptPort(47334, "Target port (MindsDB default)", True)
    ssl = OptBool(False, "SSL enabled: true/false", True, advanced=True)
    base_path = OptString("/", "MindsDB base path", required=False)
    username = OptString("", "MindsDB username (for authenticated probe)", required=False)
    password = OptString("", "MindsDB password (for authenticated probe)", required=False)
    active_probe = OptBool(
        False,
        "Send a safe authenticated probe to /api/files/<name> to test endpoint reachability",
        required=False,
    )

    def _prefix(self) -> str:
        bp = str(self.base_path or "/").strip()
        if not bp.startswith("/"):
            bp = "/" + bp
        return bp.rstrip("/")

    @staticmethod
    def _parse_version(version_text: str):
        m = re.match(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", str(version_text or "").strip())
        if not m:
            return ()
        return tuple(int(p) for p in m.groups())

    def _auth_headers(self) -> dict:
        if not self.username or not self.password:
            return {}
        response = self.http_request(
            method="POST",
            path=f"{self._prefix()}/api/login",
            json={"username": str(self.username), "password": str(self.password)},
            timeout=max(int(self.timeout or 10), 10),
        )
        if not response or response.status_code != 200:
            return {}
        try:
            token = (response.json() or {}).get("token")
        except Exception:
            token = None
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}"}

    def run(self):
        try:
            status = self.http_request(
                method="GET",
                path=f"{self._prefix()}/api/status",
                timeout=max(int(self.timeout or 10), 10),
            )
            if not status or status.status_code != 200:
                return False

            try:
                status_json = status.json() or {}
            except Exception:
                self.set_info(
                    severity="low",
                    cve="CVE-2026-27483",
                    reason="MindsDB-like /api/status reachable but JSON parsing failed",
                )
                return True

            version_text = str(status_json.get("mindsdb_version", "")).strip()
            version = self._parse_version(version_text)
            auth_enabled = bool((status_json.get("auth") or {}).get("http_auth_enabled"))

            if not version:
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-27483",
                    reason="MindsDB detected but version string is missing/unparseable",
                )
                return True

            if version >= (25, 9, 1, 1):
                return False

            if version < (25, 4, 1, 0):
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-27483",
                    reason=(
                        f"MindsDB {version_text} detected (< 25.4.1.0, likely vulnerable). "
                        "Exploit path may need python-version-specific adjustment."
                    ),
                )
                return True

            if not self.active_probe:
                sev = "high" if not auth_enabled else "medium"
                self.set_info(
                    severity=sev,
                    cve="CVE-2026-27483",
                    reason=(
                        f"MindsDB {version_text} detected in vulnerable range (< 25.9.1.1); "
                        f"http_auth_enabled={auth_enabled}"
                    ),
                )
                return True

            headers = {}
            if auth_enabled:
                headers = self._auth_headers()
                if not headers:
                    self.set_info(
                        severity="medium",
                        cve="CVE-2026-27483",
                        reason=(
                            f"MindsDB {version_text} appears vulnerable but authenticated probe skipped: "
                            "set valid username/password for active_probe"
                        ),
                    )
                    return True

            marker = self.random_text(8).lower()
            probe = self.http_request(
                method="PUT",
                path=f"{self._prefix()}/api/files/{marker}",
                data={"name": marker, "source": marker, "source_type": "file"},
                files={"file": ("probe.txt", "kittysploit-probe", "text/plain")},
                headers=headers,
                timeout=max(int(self.timeout or 10), 10),
            )

            if probe and probe.status_code in (200, 201, 204, 400):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-27483",
                    reason=(
                        f"MindsDB {version_text} in vulnerable range and /api/files accepts crafted PUT "
                        f"(HTTP {probe.status_code})"
                    ),
                )
                return True

            self.set_info(
                severity="medium",
                cve="CVE-2026-27483",
                reason=(
                    f"MindsDB {version_text} in vulnerable range but active /api/files probe was inconclusive "
                    f"(HTTP {probe.status_code if probe else 'no response'})"
                ),
            )
            return True
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
