#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Apache Solr CVE-2026-44825 detection",
        "description": (
            "Detects Apache Solr instances in the CVE-2026-44825 affected version range "
            "(9.4.x through 9.10.x before 9.10.2, and 10.0.0) and reports whether "
            "admin endpoints require authentication."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-44825",
        "references": [
            "https://solr.apache.org/",
            "https://www.cve.org/CVERecord?id=CVE-2026-44825",
        ],
        "modules": [
            "exploits/multi/http/solr_cve_2026_44825_rce",
        ],
        "tags": ["web", "scanner", "solr", "apache", "rce", "cve-2026-44825"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 'medium',
        'noise': 'low',
        'value': 'medium',
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    base_path = OptString("/solr", "Solr base URL path", required=False)

    _VERSION_PATTERNS = (
        re.compile(r"solr-spec-version[^0-9]*([\d.]+)", re.I),
        re.compile(r"solr-impl-version[^0-9]*([\d.]+)", re.I),
    )

    def _solr_path(self, suffix: str) -> str:
        base = str(self.base_path or "/solr").strip()
        if not base.startswith("/"):
            base = f"/{base}"
        base = base.rstrip("/")
        if not suffix.startswith("/"):
            suffix = f"/{suffix}"
        return f"{base}{suffix}"

    @staticmethod
    def _extract_version(body: str) -> str:
        for pattern in Module._VERSION_PATTERNS:
            match = pattern.search(body or "")
            if match:
                return match.group(1)
        return ""

    @staticmethod
    def _is_vulnerable_version(version: str):
        if not version:
            return None
        try:
            parts = [int(part) for part in version.split(".")]
        except ValueError:
            return None

        if not parts:
            return None

        major = parts[0]
        minor = parts[1] if len(parts) > 1 else 0
        patch = parts[2] if len(parts) > 2 else 0

        if major == 9 and 4 <= minor <= 10:
            if minor == 10 and patch > 1:
                return False
            return True
        if major == 10:
            return minor == 0 and patch == 0
        return False

    def _looks_like_solr(self, response, body: str) -> bool:
        if not response:
            return False
        text = (body or "").lower()
        server = str(response.headers.get("Server", "")).lower()
        return "solr" in text or "solr" in server or "solr-spec-version" in text

    def _auth_required(self, initial_status: int) -> bool:
        if initial_status == 401:
            return True
        for suffix in ("/admin/cores?action=STATUS", "/admin/collections?action=LIST"):
            response = self.http_request(
                method="GET",
                path=self._solr_path(suffix),
                allow_redirects=False,
                timeout=8,
            )
            if response and response.status_code == 401:
                return True
        return False

    def run(self):
        try:
            response = self.http_request(
                method="GET",
                path=self._solr_path("/admin/info/system"),
                allow_redirects=False,
                timeout=8,
            )
            if not response or response.status_code not in (200, 401):
                return False

            body = response.text or ""
            if not self._looks_like_solr(response, body):
                return False

            version = self._extract_version(body)
            vulnerable = self._is_vulnerable_version(version)
            auth_required = self._auth_required(response.status_code)

            if vulnerable is False:
                self.set_info(
                    severity="info",
                    cve="CVE-2026-44825",
                    version=version or "unknown",
                    reason=(
                        f"Apache Solr {version or 'detected'} outside CVE-2026-44825 affected range"
                    ),
                    auth_required=auth_required,
                )
                return False

            if vulnerable is None:
                self.set_info(
                    severity="medium",
                    cve="CVE-2026-44825",
                    reason="Apache Solr detected but version could not be parsed",
                    auth_required=auth_required,
                )
                return True

            self.set_info(
                severity="critical",
                cve="CVE-2026-44825",
                version=version,
                reason=(
                    f"Apache Solr {version} is within CVE-2026-44825 affected range"
                    + (" (auth required)" if auth_required else " (no auth on admin endpoints)")
                ),
                auth_required=auth_required,
            )
            return True
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
