#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.camaleon_cve_2024_46987 import (
    camaleon_page_path,
    normalize_camaleon_base_path,
)
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Camaleon CMS CVE-2024-46987 detection",
        "description": (
            "Fingerprints Camaleon CMS and flags versions <= 2.9.0 affected by CVE-2024-46987 "
            "(authenticated path traversal in /admin/media/download_private_file)."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2024-46987",
        "references": [
            "https://github.com/owen2345/camaleon-cms",
            "https://github.com/owen2345/camaleon-cms/releases/tag/2.9.0",
        ],
        "modules": [
            "auxiliary/admin/http/camaleon_cms_cve_2024_46987_traversal",
        ],
        "tags": ["web", "scanner", "camaleon", "rails", "lfi", "path-traversal", "cve-2024-46987"],
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
                    "auxiliary/admin/http/camaleon_cms_cve_2024_46987_traversal",
                ],
            },
        },
    }

    base_path = OptString("/", "Camaleon base URL path", required=False)

    _VERSION_RES = (
        re.compile(r"camaleon[_\s-]?cms[^0-9]{0,40}(\d+\.\d+\.\d+)", re.I),
        re.compile(r"camaleon[^0-9]{0,20}(\d+\.\d+\.\d+)", re.I),
        re.compile(r'["\']camaleon[_\s-]?(\d+\.\d+\.\d+)["\']', re.I),
        re.compile(r"version[^0-9]{0,24}(\d+\.\d+\.\d+)", re.I),
    )

    def _page_path(self, suffix: str) -> str:
        return camaleon_page_path(self.base_path, suffix)

    @staticmethod
    def _version_tuple(value: str):
        parts = []
        for token in str(value).split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _version_lte(self, value: str, limit: str = "2.9.0") -> bool:
        return self._version_tuple(value) <= self._version_tuple(limit)

    def _extract_version(self, body: str) -> str:
        for pattern in self._VERSION_RES:
            match = pattern.search(body or "")
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def _fingerprint_camaleon(body: str) -> bool:
        if not body:
            return False
        low = body.lower()
        return (
            "camaleon" in low
            or "camaleon_cms" in low
            or ("/camaleon/" in low and ("gem" in low or "rails" in low))
        )

    def run(self):
        try:
            bodies = []
            for rel in ("/", "/admin/login", "/admin"):
                response = self.http_request(
                    method="GET",
                    path=self._page_path(rel),
                    allow_redirects=True,
                    timeout=15,
                )
                if response and response.status_code == 200 and response.text:
                    bodies.append(response.text)

            if not bodies:
                return False

            combined = "\n".join(bodies)
            if not self._fingerprint_camaleon(combined):
                return False

            version = self._extract_version(combined)
            if not version:
                self.set_info(
                    severity="info",
                    cve="CVE-2024-46987",
                    reason="Camaleon CMS detected but version could not be extracted",
                    path=normalize_camaleon_base_path(self.base_path) or "/",
                )
                return True

            if self._version_lte(version, "2.9.0"):
                self.set_info(
                    severity="high",
                    cve="CVE-2024-46987",
                    reason=(
                        f"Camaleon CMS {version} detected (<= 2.9.0); "
                        "within CVE-2024-46987 affected range"
                    ),
                    version=version,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="info",
                reason=f"Camaleon CMS {version} detected; appears patched for CVE-2024-46987",
                version=version,
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
