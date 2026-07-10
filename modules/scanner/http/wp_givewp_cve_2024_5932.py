#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "WordPress GiveWP CVE-2024-5932 detection",
        "description": "Detects exposed GiveWP plugin versions affected by PHP object injection RCE.",
        "author": "KittySploit Team",
        "cve": "CVE-2024-5932",
        "severity": "critical",
        "tags": ["web", "scanner", "wordpress", "givewp", "rce", "cve-2024-5932"],
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2024-5932",
            "https://github.com/EQSTLab/CVE-2024-8353",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
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
         'confidence_min': {'wordpress': 0.3},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    max_vulnerable_version = OptString("3.14.1", "Highest GiveWP version treated as vulnerable", required=False, advanced=True)

    def _prefix(self) -> str:
        path = str(self.base_path or "/").strip()
        if not path.startswith("/"):
            path = "/" + path
        return path.rstrip("/")

    def _path(self, suffix: str) -> str:
        prefix = self._prefix()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{prefix}{suffix}" if prefix else suffix

    @staticmethod
    def _parse_version(text: str) -> str:
        if not text:
            return ""
        patterns = [
            r"^\s*Stable tag:\s*([0-9][0-9A-Za-z.\-_]*)\s*$",
            r"^\s*Version:\s*([0-9][0-9A-Za-z.\-_]*)\s*$",
            r"Give(?:WP)?\s+(?:Donation\s+Plugin\s+)?(?:version\s*)?([0-9]+(?:\.[0-9]+){1,3})",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1).strip()
        return ""

    @staticmethod
    def _version_tuple(value: str) -> Tuple[int, ...]:
        parts = []
        for item in re.findall(r"\d+", value or "")[:4]:
            try:
                parts.append(int(item))
            except Exception:
                parts.append(0)
        return tuple(parts or [0])

    def _leq(self, left: str, right: str) -> bool:
        a = list(self._version_tuple(left))
        b = list(self._version_tuple(right))
        width = max(len(a), len(b))
        a.extend([0] * (width - len(a)))
        b.extend([0] * (width - len(b)))
        return tuple(a) <= tuple(b)

    def _fetch_plugin_version(self) -> Tuple[str, str]:
        candidates = [
            "/wp-content/plugins/give/readme.txt",
            "/wp-content/plugins/give/give.php",
            "/wp-content/plugins/give/src/Give/ServiceProviders/ServiceProvider.php",
        ]
        for suffix in candidates:
            response = self.http_request(method="GET", path=self._path(suffix), allow_redirects=False)
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            version = self._parse_version(body)
            if version:
                return version, self._path(suffix)
            if "GiveWP" in body or "Give - Donation Plugin" in body or "givewp" in body.lower():
                return "", self._path(suffix)
        return "", ""

    def run(self):
        version, evidence_path = self._fetch_plugin_version()
        if not evidence_path:
            self.set_info(severity="info", reason="GiveWP plugin was not detected")
            return False

        if version:
            max_version = str(self.max_vulnerable_version or "3.14.1")
            if self._leq(version, max_version):
                self.set_info(
                    severity="critical",
                    reason=f"GiveWP {version} detected at {evidence_path}; <= {max_version} is treated as CVE-2024-5932 exposure",
                    cve="CVE-2024-5932",
                    service="wordpress",
                )
                return True
            self.set_info(
                severity="info",
                reason=f"GiveWP {version} detected at {evidence_path}; version is above configured vulnerable threshold",
                service="wordpress",
            )
            return False

        self.set_info(
            severity="medium",
            reason=f"GiveWP plugin detected at {evidence_path}, but version could not be extracted",
            cve="CVE-2024-5932",
            service="wordpress",
        )
        return True

