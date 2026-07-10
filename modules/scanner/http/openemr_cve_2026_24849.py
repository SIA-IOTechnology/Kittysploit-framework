#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.openemr_cve_2026_24849 import (
    LOGIN_PATH,
    looks_like_openemr_login,
    openemr_path,
)

_PATCHED_VERSION = (7, 0, 4)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "OpenEMR CVE-2026-24849 detection",
        "description": (
            "Fingerprints OpenEMR and flags versions < 7.0.4 affected by CVE-2026-24849 "
            "(authenticated arbitrary file read in Fax/SMS EtherFax)."
        ),
        "author": ["doany1", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-24849",
        "references": [
            "https://github.com/openemr/openemr/security/advisories/GHSA-w6vc-hx2x-48pc",
            "https://nvd.nist.gov/vuln/detail/CVE-2026-24849",
        ],
        "modules": [
            "exploits/multi/http/openemr_cve_2026_24849_file_read",
        ],
        "tags": ["web", "scanner", "openemr", "file-read", "cve-2026-24849"],
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
                    "exploits/multi/http/openemr_cve_2026_24849_file_read",
                ],
            },
        },
    }

    port = OptPort(80, "OpenEMR HTTP port", True)
    ssl = OptBool(False, "Use HTTPS", True, advanced=True)
    base_path = OptString("/openemr", "OpenEMR base path (use / if installed at web root)", required=True)
    site = OptString("default", "OpenEMR site id", required=True)

    _VERSION_PATTERNS = (
        re.compile(r"OpenEMR\s+v?(\d+\.\d+\.\d+)", re.I),
        re.compile(r"v(\d+\.\d+\.\d+)\s*\|\s*OpenEMR", re.I),
        re.compile(r"openemr[^0-9]{0,20}(\d+\.\d+\.\d+)", re.I),
    )

    @staticmethod
    def _version_tuple(value: str) -> Tuple[int, ...]:
        parts = []
        for item in re.findall(r"\d+", value or "")[:4]:
            parts.append(int(item))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _parse_version(self, text: str) -> str:
        for pattern in self._VERSION_PATTERNS:
            match = pattern.search(text or "")
            if match:
                return match.group(1).strip()
        return ""

    def _is_vulnerable(self, version: str) -> bool:
        return self._version_tuple(version) < _PATCHED_VERSION

    def run(self):
        try:
            resp = self.http_request(
                method="GET",
                path=openemr_path(self.base_path, LOGIN_PATH),
                params={"site": self.site or "default"},
                allow_redirects=True,
                timeout=max(int(self.timeout or 10), 15),
            )
            if not resp or resp.status_code != 200:
                return False

            body = resp.text or ""
            if not looks_like_openemr_login(body):
                return False

            version = self._parse_version(body)
            path = openemr_path(self.base_path, LOGIN_PATH)

            if not version:
                self.set_info(
                    severity="info",
                    cve="CVE-2026-24849",
                    reason="OpenEMR login detected but version could not be extracted",
                    path=path,
                )
                return True

            if self._is_vulnerable(version):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-24849",
                    reason=(
                        f"OpenEMR {version} detected at {path}; "
                        "< 7.0.4 is within CVE-2026-24849 affected range"
                    ),
                    version=version,
                    path=path,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="info",
                reason=f"OpenEMR {version} detected at {path}; appears patched for CVE-2026-24849",
                version=version,
                path=path,
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
