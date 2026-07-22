#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "wpzoom-portfolio"
_VULN_HIGH = (1, 4, 21)
_CVE = "CVE-2026-49069"


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "WordPress WPZOOM Portfolio CVE-2026-49069 detection",
        "description": (
            "Detects WPZOOM Portfolio plugin versions <= 1.4.21 affected by "
            "unauthenticated reflected XSS (CVE-2026-49069)."
        ),
        "author": ["Kent Apostol", "KittySploit Team"],
        "severity": "medium",
        "cve": _CVE,
        "references": [
            "https://wordpress.org/plugins/wpzoom-portfolio/",
            "https://www.cve.org/CVERecord?id=CVE-2026-49069",
        ],
        "modules": [
            "auxiliary/scanner/http/wpzoom_portfolio_cve_2026_49069_xss",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "wpzoom-portfolio",
            "xss",
            "reflected-xss",
            "unauthenticated",
            "cve-2026-49069",
        ],
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

    base_path = OptString("/", "WordPress base path", required=False)

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or self.path or "/")

    def _plugin_readme_path(self) -> str:
        return self.wp_plugin_path(self._wp_base(), _PLUGIN, "readme.txt")

    def run(self):
        readme_path = self._plugin_readme_path()
        response = self.http_request(
            method="GET",
            path=readme_path,
            allow_redirects=True,
            timeout=10,
        )
        if not response or response.status_code != 200:
            self.set_info(severity="info", reason="WPZOOM Portfolio plugin not detected")
            return False

        version = self.wp_extract_version_from_readme(response.text or "")
        if not version:
            self.set_info(
                severity="info",
                reason=f"WPZOOM Portfolio detected at {readme_path}, but version could not be extracted",
                service="wordpress",
            )
            return False

        if not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            self.set_info(
                severity="info",
                reason=(
                    f"WPZOOM Portfolio {version} detected at {readme_path}; "
                    "version is above the patched threshold (> 1.4.21)"
                ),
                service="wordpress",
            )
            return False

        self.set_info(
            severity="medium",
            cve=_CVE,
            version=version,
            reason=f"WPZOOM Portfolio version {version} <= 1.4.21 detected",
            service="wordpress",
            endpoint="/wp-admin/admin-ajax.php",
        )
        return True
