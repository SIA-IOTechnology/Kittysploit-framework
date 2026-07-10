#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache Tomcat CVE-2026-43512 detection",
        "description": (
            "Fingerprints Apache Tomcat and flags versions affected by CVE-2026-43512 "
            "(DIGEST authentication bypass): 9.0.x < 9.0.118, 10.1.x < 10.1.55, "
            "11.0.x < 11.0.22, 8.5.x <= 8.5.100."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-43512",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-43512",
        ],
        "modules": [
            "auxiliary/admin/http/apache_tomcat_cve_2026_43512_digest_bypass",
        ],
        "tags": [
            "web",
            "scanner",
            "tomcat",
            "apache",
            "digest",
            "auth-bypass",
            "cve-2026-43512",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": ["tomcat", "java"],
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
                    {"capability": "auth_bypass", "from_detail": "digest"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "auxiliary/admin/http/apache_tomcat_cve_2026_43512_digest_bypass",
                ],
            },
        },
    }

    port = OptPort(8080, "Tomcat HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)

    _VERSION_PATTERNS = (
        re.compile(r"Apache Tomcat/([\d.]+)", re.I),
        re.compile(r"Tomcat/([\d.]+)", re.I),
        re.compile(r"Server:\s*Apache-Coyote/[\d.]+\s*\(.*?Tomcat/([\d.]+)", re.I),
    )

    _PROBE_PATHS = ("/", "/manager/html", "/docs/")

    @staticmethod
    def _version_tuple(value: str) -> Tuple[int, ...]:
        cleaned = re.sub(r"-M\d+$", "", str(value or "").strip(), flags=re.I)
        parts = []
        for token in cleaned.split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _parse_version(self, text: str, headers: dict) -> str:
        blob = (text or "") + "\n" + " ".join(
            f"{k}: {v}" for k, v in (headers or {}).items()
        )
        for pattern in self._VERSION_PATTERNS:
            match = pattern.search(blob)
            if match:
                return match.group(1).strip()
        return ""

    def _is_vulnerable(self, version: str) -> Optional[bool]:
        if not version:
            return None
        major, minor, patch = self._version_tuple(version)
        if major == 11 and minor == 0:
            return (major, minor, patch) < (11, 0, 22)
        if major == 10 and minor == 1:
            return (major, minor, patch) < (10, 1, 55)
        if major == 9 and minor == 0:
            return (major, minor, patch) < (9, 0, 118)
        if major == 8 and minor == 5:
            return (major, minor, patch) <= (8, 5, 100)
        if major == 7:
            return (major, minor, patch) <= (7, 0, 109)
        return False

    @staticmethod
    def _looks_like_tomcat(body: str, headers: dict) -> bool:
        text = (body or "").lower()
        if "apache tomcat" in text or "tomcat" in text:
            return True
        server = str((headers or {}).get("Server", "")).lower()
        return "tomcat" in server or "coyote" in server

    def run(self):
        try:
            detected = False
            version = ""
            evidence_path = ""

            for path in self._PROBE_PATHS:
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=True,
                    timeout=max(int(self.timeout or 10), 10),
                )
                if not response:
                    continue
                body = response.text or ""
                headers = dict(response.headers)
                if self._looks_like_tomcat(body, headers):
                    detected = True
                    evidence_path = path
                parsed = self._parse_version(body, headers)
                if parsed:
                    version = parsed
                    evidence_path = evidence_path or path
                if detected and version:
                    break

            if not detected:
                return False

            if not version:
                self.set_info(
                    severity="info",
                    cve="CVE-2026-43512",
                    reason="Apache Tomcat detected but version could not be extracted",
                    path=evidence_path,
                )
                return True

            if self._is_vulnerable(version):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-43512",
                    reason=(
                        f"Apache Tomcat {version} detected at {evidence_path}; "
                        "within CVE-2026-43512 affected range (DIGEST auth must be enabled)"
                    ),
                    version=version,
                    path=evidence_path,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="info",
                reason=(
                    f"Apache Tomcat {version} detected at {evidence_path}; "
                    "appears patched for CVE-2026-43512"
                ),
                version=version,
                path=evidence_path,
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
