#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_THEME = "bricks"
_VULN_HIGH = (1, 9, 6)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Bricks Builder CVE-2024-25600 detection",
        "description": (
            "Detects WordPress Bricks theme <= 1.9.6 affected by CVE-2024-25600 "
            "(unauthenticated render_element RCE)."
        ),
        "author": ["watchTowr", "KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2024-25600",
        "references": [
            "https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT",
            "https://wpscan.com/vulnerability/8bab5266-7154-4b65-b5bc-07a91b379415/",
        ],
        "modules": [
            "exploits/multi/http/bricks_builder_cve_2024_25600_rce",
        ],
        "tags": ["web", "scanner", "wordpress", "bricks", "rce"],
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
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''}],
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

    def _fetch_theme_version(self) -> Tuple[str, str]:
        candidates = [
            self._path(f"/wp-content/themes/{_THEME}/style.css"),
            self._path(f"/wp-content/themes/{_THEME}/readme.txt"),
        ]
        for path in candidates:
            response = self.http_request(method="GET", path=path, allow_redirects=True)
            if not response or response.status_code != 200:
                continue
            body = response.text or ""
            for pattern in (
                r"Version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                r"Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
            ):
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return match.group(1).strip(), path
            if "bricks" in body.lower():
                return "", path
        return "", ""

    def run(self):
        try:
            version, evidence_path = self._fetch_theme_version()
            if not evidence_path:
                return False

            if version:
                if self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
                    self.set_info(
                        severity="critical",
                        cve="CVE-2024-25600",
                        reason=(
                            f"Bricks {version} detected at {evidence_path}; "
                            f"<= {_VULN_HIGH[0]}.{_VULN_HIGH[1]}.{_VULN_HIGH[2]} "
                            "is within CVE-2024-25600 affected range"
                        ),
                        version=version,
                        service="wordpress",
                    )
                    return True
                self.set_info(
                    severity="info",
                    reason=f"Bricks {version} detected; appears patched for CVE-2024-25600",
                    version=version,
                    service="wordpress",
                )
                return False

            self.set_info(
                severity="medium",
                cve="CVE-2024-25600",
                reason=f"Bricks theme detected at {evidence_path}, but version could not be extracted",
                service="wordpress",
            )
            return True
        except Exception:
            return False
