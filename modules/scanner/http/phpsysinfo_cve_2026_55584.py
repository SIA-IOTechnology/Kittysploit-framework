#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.phpsysinfo import Phpsysinfo

_AFFECTED_VERSION = "3.4.5"


class Module(Scanner, Http_client, Phpsysinfo):
    __info__ = {
        "name": "phpSysInfo CVE-2026-55584 detection",
        "description": (
            "Fingerprints phpSysInfo and flags versions <= 3.4.5 affected by CVE-2026-55584 "
            "(PSI_ALLOWED IP allowlist bypass via X-Forwarded-For / Client-IP)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-55584",
        "references": [
            "https://github.com/phpsysinfo/phpsysinfo/security/advisories/GHSA-786w-p5pm-cvgh",
            "https://www.cve.org/CVERecord?id=CVE-2026-55584",
        ],
        "modules": [
            "auxiliary/admin/http/phpsysinfo_cve_2026_55584_info_disclosure",
        ],
        "tags": [
            "web",
            "scanner",
            "phpsysinfo",
            "disclosure",
            "allowlist",
            "cve-2026-55584",
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
                    "auxiliary/admin/http/phpsysinfo_cve_2026_55584_info_disclosure",
                ],
            },
        },
    }

    base_path = OptString("/", "phpSysInfo base URL path (e.g. /phpsysinfo)", required=False)

    def run(self):
        try:
            version = ""
            evidence_path = ""
            for path in self.phpsysinfo_index_paths(self.base_path):
                response = self.http_request(
                    method="GET",
                    path=path,
                    allow_redirects=True,
                    timeout=max(int(self.timeout or 10), 10),
                )
                if not response or response.status_code != 200:
                    continue
                body = response.text or ""
                if not self.phpsysinfo_looks_like_page(body):
                    continue
                evidence_path = path
                version = self.phpsysinfo_extract_version(body)
                if version:
                    break

            if not evidence_path:
                return False

            if not version:
                self.set_info(
                    severity="info",
                    cve="CVE-2026-55584",
                    reason="phpSysInfo detected but version could not be extracted",
                    path=evidence_path,
                )
                return True

            if self.phpsysinfo_version_lte(version, _AFFECTED_VERSION):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-55584",
                    reason=(
                        f"phpSysInfo {version} detected at {evidence_path}; "
                        f"<= {_AFFECTED_VERSION} is within CVE-2026-55584 affected range"
                    ),
                    version=version,
                    path=evidence_path,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="info",
                reason=(
                    f"phpSysInfo {version} detected at {evidence_path}; "
                    "appears patched for CVE-2026-55584"
                ),
                version=version,
                path=evidence_path,
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
