#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Fortinet FortiSandbox CVE-2026-25089 detection",
        "description": (
            "Fingerprints FortiSandbox and flags versions affected by CVE-2026-25089 "
            "(unauthenticated OS command injection in the VNC start handler): "
            "5.0.0–5.0.5, 4.4.0–4.4.8, and all 4.2.x."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-25089",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-25089",
            "https://www.fortiguard.com/psirt/FG-IR-26-141",
        ],
        "modules": [
            "exploits/linux/http/fortinet_fortisandbox_cve_2026_25089_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "fortinet",
            "fortisandbox",
            "command-injection",
            "rce",
            "cve-2026-25089",
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
                "tech_hints_any": ["fortinet", "fortisandbox"],
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
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/linux/http/fortinet_fortisandbox_cve_2026_25089_rce",
                ],
            },
        },
    }

    port = OptPort(443, "FortiSandbox HTTPS port", True)
    ssl = OptBool(True, "Use HTTPS", True, advanced=True)

    _VERSION_PATTERNS = (
        re.compile(r"fortisandbox[^0-9]{0,24}(5\.\d+\.\d+)", re.I),
        re.compile(r"fortisandbox[^0-9]{0,24}(4\.\d+\.\d+)", re.I),
        re.compile(r'"version"\s*:\s*"(5\.\d+\.\d+)"', re.I),
        re.compile(r'"version"\s*:\s*"(4\.\d+\.\d+)"', re.I),
        re.compile(r"FortiSandbox\s+v?(5\.\d+\.\d+)", re.I),
        re.compile(r"FortiSandbox\s+v?(4\.\d+\.\d+)", re.I),
    )

    _PROBE_PATHS = ("/", "/login")

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
        if major == 5 and minor == 0:
            return patch <= 5
        if major == 4 and minor == 4:
            return patch <= 8
        if major == 4 and minor == 2:
            return True
        return False

    @staticmethod
    def _looks_like_fortisandbox(body: str, headers: dict) -> bool:
        text = (body or "").lower()
        if "fortisandbox" in text or "forti sandbox" in text:
            return True
        blob = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
        return "fortinet" in blob and "sandbox" in text

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
                if not response or response.status_code != 200:
                    continue
                body = response.text or ""
                headers = dict(response.headers)
                if self._looks_like_fortisandbox(body, headers):
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
                    cve="CVE-2026-25089",
                    reason="FortiSandbox detected but version could not be extracted",
                    path=evidence_path,
                )
                return True

            if self._is_vulnerable(version):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-25089",
                    reason=(
                        f"FortiSandbox {version} detected at {evidence_path}; "
                        "within CVE-2026-25089 affected range"
                    ),
                    version=version,
                    path=evidence_path,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="info",
                reason=(
                    f"FortiSandbox {version} detected at {evidence_path}; "
                    "appears patched for CVE-2026-25089"
                ),
                version=version,
                path=evidence_path,
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
