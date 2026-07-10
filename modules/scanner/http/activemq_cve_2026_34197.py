#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache ActiveMQ CVE-2026-34197 detection",
        "description": (
            "Fingerprints Apache ActiveMQ Classic and flags versions affected by "
            "CVE-2026-34197 (Jolokia addNetworkConnector RCE): < 5.19.4 and "
            "6.0.0 through 6.2.2."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-34197",
        "references": [
            "https://activemq.apache.org/security-advisories.data/CVE-2026-34197-announcement.txt",
            "https://www.cve.org/CVERecord?id=CVE-2026-34197",
        ],
        "modules": [
            "exploits/linux/http/activemq_cve_2026_34197_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "activemq",
            "jolokia",
            "java",
            "rce",
            "cve-2026-34197",
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
                "tech_hints_any": ["activemq", "java"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/api/jolokia"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/linux/http/activemq_cve_2026_34197_rce",
                ],
            },
        },
    }

    port = OptPort(8161, "ActiveMQ web console port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)

    _VERSION_PATTERNS = (
        re.compile(r"ActiveMQ\s+Version:\s*([\d.]+)", re.I),
        re.compile(r"Apache\s+ActiveMQ\s+([\d.]+)", re.I),
        re.compile(r'"ActiveMQVersion"\s*:\s*"([\d.]+)"', re.I),
        re.compile(r"activemq[^0-9]{0,20}([\d]+\.[\d]+\.[\d]+)", re.I),
    )

    _PROBE_PATHS = ("/admin/", "/api/jolokia/", "/")

    @staticmethod
    def _version_tuple(value: str) -> Tuple[int, ...]:
        parts = []
        for token in re.findall(r"\d+", value or ""):
            parts.append(int(token))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _parse_version(self, text: str) -> str:
        for pattern in self._VERSION_PATTERNS:
            match = pattern.search(text or "")
            if match:
                return match.group(1).strip()
        return ""

    def _is_vulnerable(self, version: str) -> Optional[bool]:
        if not version:
            return None
        major, minor, patch = self._version_tuple(version)
        if major == 5:
            return (major, minor, patch) < (5, 19, 4)
        if major == 6:
            return (6, 0, 0) <= (major, minor, patch) < (6, 2, 3)
        return False

    @staticmethod
    def _looks_like_activemq(body: str, headers: dict) -> bool:
        text = (body or "").lower()
        if "activemq" in text or "apache activemq" in text or "jolokia" in text:
            return True
        blob = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
        return "activemq" in blob

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
                if self._looks_like_activemq(body, headers):
                    detected = True
                    evidence_path = path
                parsed = self._parse_version(body)
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
                    cve="CVE-2026-34197",
                    reason="ActiveMQ detected but version could not be extracted",
                    path=evidence_path,
                )
                return True

            if self._is_vulnerable(version):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-34197",
                    reason=(
                        f"Apache ActiveMQ {version} detected at {evidence_path}; "
                        "within CVE-2026-34197 affected range"
                    ),
                    version=version,
                    path=evidence_path,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="info",
                reason=(
                    f"Apache ActiveMQ {version} detected at {evidence_path}; "
                    "appears patched for CVE-2026-34197"
                ),
                version=version,
                path=evidence_path,
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
