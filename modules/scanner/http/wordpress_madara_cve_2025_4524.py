#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2025-4524 — Madara theme/plugin version detection."""

import re
from typing import Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_THEME = "madara"
_PLUGIN = "madara-core"
_VULN_HIGH = (1, 6, 0, 5)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress Madara CVE-2025-4524 detection",
        "description": (
            "Detects Madara theme/plugin versions <= 1.6.0.5 affected by CVE-2025-4524 "
            "(unauthenticated LFI via madara_load_more template parameter)."
        ),
        "author": "KittySploit Team",
        "severity": "high",
        "cve": "CVE-2025-4524",
        "modules": [
            "auxiliary/scanner/http/wordpress_madara_cve_2025_4524_lfi",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "lfi",
            "madara",
            "path-traversal",
            "cve-2025-4524",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
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
                "confidence_min": {"wordpress": 0.3},
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
                    "auxiliary/scanner/http/wordpress_madara_cve_2025_4524_lfi",
                ],
            },
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

    def _fetch_version(self) -> Tuple[str, str]:
        wp_base = self._wp_base()
        for slug in (_PLUGIN, _THEME):
            version = self.wp_plugin_version(slug, wp_base)
            if version:
                return version, self.wp_plugin_path(wp_base, slug, "readme.txt")

        candidates = [
            self.wp_plugin_path(wp_base, _PLUGIN, "readme.txt"),
            self.wp_plugin_path(wp_base, _PLUGIN, "madara-core.php"),
            f"{self._path('/wp-content/themes/madara/style.css')}",
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
            if "madara" in body.lower() or "Madara" in body:
                return "", path
        return "", ""

    def run(self):
        version, evidence_path = self._fetch_version()
        if not evidence_path:
            return False

        if version:
            if self.wp_version_in_range(version, (0, 0, 0, 0), _VULN_HIGH):
                self.set_info(
                    severity="high",
                    cve="CVE-2025-4524",
                    reason=(
                        f"Madara {version} detected at {evidence_path}; "
                        f"<= {_VULN_HIGH[0]}.{_VULN_HIGH[1]}.{_VULN_HIGH[2]}.{_VULN_HIGH[3]} "
                        "is within CVE-2025-4524 affected range"
                    ),
                    version=version,
                    service="wordpress",
                )
                return True
            self.set_info(
                severity="info",
                reason=f"Madara {version} detected at {evidence_path}; appears patched for CVE-2025-4524",
                version=version,
                service="wordpress",
            )
            return False

        self.set_info(
            severity="medium",
            cve="CVE-2025-4524",
            reason=f"Madara theme/plugin detected at {evidence_path}, but version could not be extracted",
            service="wordpress",
        )
        return True
