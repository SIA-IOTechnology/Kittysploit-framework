#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "FUXA CVE-2025-69985 detection",
        "description": (
            "Fingerprints FUXA SCADA/HMI and flags versions <= 1.2.8 affected by CVE-2025-69985 "
            "(unauthenticated /api/runscript RCE)."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2025-69985",
        "references": [
            "https://github.com/joshuavanderpoll/CVE-2025-69985",
            "https://github.com/frangoteam/FUXA",
        ],
        "modules": [
            "exploits/http/fuxa_cve_2025_69985_rce",
        ],
        "tags": ["web", "scanner", "fuxa", "scada", "cve-2025-69985", "rce"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.2,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(1881, "Target port (FUXA default)", True)
    ssl = OptBool(False, "SSL enabled: true/false", True, advanced=True)
    base_path = OptString("/", "URL prefix if FUXA is behind a path", required=False)

    _VERSION_RE = re.compile(
        r'(?:version|fuxa)[^"\']{0,24}["\'](\d+\.\d+(?:\.\d+)?)["\']',
        re.IGNORECASE,
    )

    def _api_path(self, suffix: str) -> str:
        prefix = str(self.base_path or "/").strip()
        if not prefix.startswith("/"):
            prefix = "/" + prefix
        prefix = prefix.rstrip("/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{prefix}{suffix}" if prefix else suffix

    @staticmethod
    def _version_tuple(version: str):
        parts = []
        for token in str(version).split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            parts.append(int(digits) if digits else 0)
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _version_lte(self, version: str, limit: str = "1.2.8") -> bool:
        return self._version_tuple(version) <= self._version_tuple(limit)

    def _extract_version(self, body: str) -> str:
        match = self._VERSION_RE.search(body or "")
        return match.group(1) if match else ""

    def run(self):
        try:
            detected = False
            version = ""
            evidence_path = ""
            for path in (self._api_path("/fuxa"), self._api_path("/")):
                response = self.http_request(method="GET", path=path, allow_redirects=True, timeout=15)
                if not response or response.status_code != 200:
                    continue
                body = response.text or ""
                if "fuxa" not in body.lower() and "frangoteam" not in body.lower():
                    continue
                detected = True
                evidence_path = path
                version = self._extract_version(body) or version
                if version:
                    break

            if not detected:
                return False

            if not version:
                self.set_info(
                    severity="info",
                    cve="CVE-2025-69985",
                    reason="FUXA detected but version could not be extracted",
                    path=evidence_path,
                )
                return True

            if self._version_lte(version, "1.2.8"):
                self.set_info(
                    severity="critical",
                    cve="CVE-2025-69985",
                    reason=f"FUXA {version} detected (<= 1.2.8); within CVE-2025-69985 affected range",
                    version=version,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="info",
                reason=f"FUXA {version} detected; appears patched for CVE-2025-69985",
                version=version,
            )
            return False
        except Exception as exc:
            print_error(f"Scanner failed: {exc}")
            return False
