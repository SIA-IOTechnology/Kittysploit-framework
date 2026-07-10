#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "breeze"
_VULN_HIGH = (2, 4, 4)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Breeze Cache CVE-2026-3844 detection",
        "description": (
            "Detects Breeze Cache <= 2.4.4 with unauthenticated arbitrary file upload via "
            "fetch_gravatar_from_remote / breeze_fetch_gravatar when local Gravatar hosting "
            "is enabled."
        ),
        "author": ["Tausif Zaman", "KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-3844",
        "references": [
            "https://www.cve.org/CVERecord?id=CVE-2026-3844",
            "https://github.com/tausifz",
        ],
        "modules": [
            "exploits/multi/http/wp_breeze_cve_2026_3844_rce",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "breeze",
            "file-upload",
            "rce",
            "unauthenticated",
            "cve-2026-3844",
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

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or self.path or "/")

    def _path(self, suffix: str) -> str:
        base = self._wp_base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _fetch_plugin_version(self) -> Tuple[str, str]:
        wp_base = self._wp_base()
        version = self.wp_plugin_version(_PLUGIN, wp_base)
        if version:
            return version, self.wp_plugin_path(wp_base, _PLUGIN, "readme.txt")

        candidates = [
            self.wp_plugin_path(wp_base, _PLUGIN, "breeze.php"),
            self.wp_plugin_path(wp_base, _PLUGIN, "inc/class-breeze-cache-cronjobs.php"),
        ]
        for path in candidates:
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            for pattern in (
                r"Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            ):
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return match.group(1).strip(), path
            if "Breeze" in body or "breeze" in body.lower():
                return "", path
        return "", ""

    def run(self):
        version, evidence_path = self._fetch_plugin_version()
        if not evidence_path:
            self.set_info(severity="info", reason="Breeze Cache plugin was not detected")
            return False

        if version:
            in_range = self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH)
            if in_range:
                self.set_info(
                    severity="critical",
                    reason=(
                        f"Breeze Cache {version} detected at {evidence_path}; "
                        f"<= {_VULN_HIGH[0]}.{_VULN_HIGH[1]}.{_VULN_HIGH[2]} is affected by "
                        "CVE-2026-3844 (requires local Gravatar hosting enabled)"
                    ),
                    cve="CVE-2026-3844",
                    service="wordpress",
                    endpoint="/wp-admin/admin-ajax.php",
                )
                return True
            self.set_info(
                severity="info",
                reason=(
                    f"Breeze Cache {version} detected at {evidence_path}; "
                    "version is above the patched threshold (2.4.5+)"
                ),
                service="wordpress",
            )
            return False

        self.set_info(
            severity="medium",
            reason=(
                f"Breeze Cache plugin detected at {evidence_path}, "
                "but version could not be extracted"
            ),
            cve="CVE-2026-3844",
            service="wordpress",
        )
        return True
