#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.detectors import detect_php


class Module(Scanner, Http_client):
    __info__ = {
        "name": "PHP CGI Argument Injection (CVE-2024-4577) detection",
        "description": (
            "Fingerprints PHP-CGI stacks and flags PHP versions in the CVE-2024-4577 affected "
            "ranges on Windows (8.1 < 8.1.29, 8.2 < 8.2.20, 8.3 < 8.3.8). Confirm exploitation "
            "with exploits/linux/http/php_cgi_cve_2024_4577_rce."
        ),
        "author": ["Orange Tsai", "watchTowr", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2024-4577",
        "references": [
            "https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/",
            "https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/",
        ],
        "modules": [
            "exploits/linux/http/php_cgi_cve_2024_4577_rce",
        ],
        "tags": ["web", "scanner", "php", "cgi", "argument-injection", "rce"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 1,
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

    target_path = OptString("/index.php", "Path to PHP entrypoint", required=False)

    @staticmethod
    def _version_tuple(version: str) -> Tuple[int, ...]:
        parts = []
        for token in re.findall(r"\d+", version or ""):
            parts.append(int(token))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _is_vulnerable_php(self, version: str) -> Optional[bool]:
        major, minor, patch = self._version_tuple(version)
        if major == 8 and minor == 1:
            return patch < 29
        if major == 8 and minor == 2:
            return patch < 20
        if major == 8 and minor == 3:
            return patch < 8
        return False

    def run(self):
        try:
            path = str(self.target_path or "/index.php").strip()
            if not path.startswith("/"):
                path = "/" + path
            response = self.http_request(method="GET", path=path, allow_redirects=True, timeout=10)
            if not response:
                return False

            version = detect_php(response) or ""
            if not version:
                headers = " ".join(f"{k}:{v}" for k, v in response.headers.items()).lower()
                if "php" not in headers and "cgi" not in headers:
                    return False
                self.set_info(
                    severity="info",
                    cve="CVE-2024-4577",
                    reason="PHP/CGI hints detected but version could not be extracted",
                    path=path,
                )
                return True

            vulnerable = self._is_vulnerable_php(version)
            if vulnerable:
                self.set_info(
                    severity="critical",
                    cve="CVE-2024-4577",
                    reason=(
                        f"PHP {version} at {path} is within CVE-2024-4577 affected ranges "
                        "(Windows CGI argument injection)"
                    ),
                    version=version,
                    path=path,
                    confidence="high",
                )
                return True

            self.set_info(
                severity="info",
                reason=f"PHP {version} at {path} appears patched for CVE-2024-4577",
                version=version,
                path=path,
            )
            return False
        except Exception:
            return False
