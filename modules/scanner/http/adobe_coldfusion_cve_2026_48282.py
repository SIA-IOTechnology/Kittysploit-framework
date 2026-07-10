#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Adobe ColdFusion CVE-2026-48282 detection",
        "description": (
            "Fingerprints Adobe ColdFusion and flags versions affected by CVE-2026-48282 "
            "(RDS path traversal): ColdFusion 2025 <= Update 9, ColdFusion 2023 <= Update 20."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-48282",
        "references": [],
        "modules": [
            "exploits/multi/http/adobe_coldfusion_cve_2026_48282_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "adobe",
            "coldfusion",
            "rds",
            "path-traversal",
            "cve-2026-48282",
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
                "tech_hints_any": ["coldfusion", "cfml"],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": ["/CFIDE/"],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "file_read", "from_detail": "rds_path"},
                    {"capability": "rce", "from_detail": ""},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "exploits/multi/http/adobe_coldfusion_cve_2026_48282_rce",
                ],
            },
        },
    }

    port = OptPort(8500, "ColdFusion HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)

    _VERSION_PATHS = (
        "/CFIDE/administrator/enter.cfm",
        "/CFIDE/administrator/index.cfm",
        "/CFIDE/administrator/",
    )
    _VERSION_PATTERNS = (
        re.compile(r"Adobe\s+ColdFusion\s+(20\d{2})\s+Update\s+(\d+)", re.I),
        re.compile(r"ColdFusion\s+(20\d{2})\s+Update\s+(\d+)", re.I),
        re.compile(r"(20\d{2})\s*,\s*0\s*,\s*(\d+)\s*,\s*\d+"),
    )
    _CF_MARKERS = (
        "coldfusion",
        "cfide",
        "adobe coldfusion",
        "cfusion",
    )

    @staticmethod
    def _parse_version(text: str) -> Tuple[Optional[int], Optional[int]]:
        if not text:
            return None, None
        for pattern in Module._VERSION_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            try:
                return int(match.group(1)), int(match.group(2))
            except (TypeError, ValueError):
                continue
        return None, None

    @staticmethod
    def _is_vulnerable(year: int, update: int) -> bool:
        if year == 2025:
            return update <= 9
        if year == 2023:
            return update <= 20
        return False

    @staticmethod
    def _looks_like_coldfusion(body: str, headers: dict) -> bool:
        haystack = (body or "").lower()
        if any(marker in haystack for marker in Module._CF_MARKERS):
            return True
        header_blob = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
        return "coldfusion" in header_blob or "cfid" in header_blob

    def _fetch_version(self) -> Tuple[Optional[int], Optional[int], str]:
        for path in self._VERSION_PATHS:
            response = self.http_request(
                method="GET",
                path=path,
                allow_redirects=True,
                timeout=max(int(self.timeout or 10), 10),
            )
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            year, update = self._parse_version(body)
            if year is not None and update is not None:
                return year, update, path
            if self._looks_like_coldfusion(body, dict(response.headers)):
                return None, None, path
        return None, None, ""

    def run(self):
        try:
            year, update, path = self._fetch_version()
            if not path:
                return False

            if year is None or update is None:
                self.set_info(
                    severity="info",
                    cve="CVE-2026-48282",
                    reason="Adobe ColdFusion detected but version could not be extracted",
                    path=path,
                )
                return True

            version_label = f"ColdFusion {year} Update {update}"
            if self._is_vulnerable(year, update):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-48282",
                    reason=(
                        f"{version_label} detected at {path}; "
                        "within CVE-2026-48282 affected range"
                    ),
                    version=version_label,
                    path=path,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="info",
                reason=f"{version_label} detected at {path}; appears patched for CVE-2026-48282",
                version=version_label,
                path=path,
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
