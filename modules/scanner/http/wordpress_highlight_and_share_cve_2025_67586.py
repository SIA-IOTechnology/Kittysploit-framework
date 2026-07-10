#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Scanner, Http_client, Wordpress):

    __info__ = {
        "name": "WordPress Highlight and Share CVE-2025-67586",
        "description": (
            "Detects vulnerable Highlight and Share plugin versions (<= 5.2.0) exposed to "
            "unauthenticated email share abuse via admin-ajax."
        ),
        "author": "KittySploit Team",
        "severity": "medium",
        "cve": "CVE-2025-67586",
        "modules": [
            "auxiliary/admin/http/wp_plugin_highlight_and_share_cve_2025_67586",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "highlight-and-share",
            "broken-access-control",
            "cve-2025-67586",
        ],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
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
         'confidence_min': {},
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.path)

    def _plugin_readme_path(self) -> str:
        return self.wp_plugin_path(self._wp_base(), "highlight-and-share", "readme.txt")

    def _is_vulnerable_version(self, version: str) -> bool:
        try:
            return self.wp_version_to_tuple(version) <= (5, 2, 0)
        except Exception:
            return False

    def run(self):
        response = self.http_request(
            method="GET",
            path=self._plugin_readme_path(),
            allow_redirects=True,
            timeout=10,
        )
        if not response or response.status_code != 200:
            return False

        version = self.wp_extract_version_from_readme(response.text or "")
        if not version:
            return False

        if not self._is_vulnerable_version(version):
            return False

        self.set_info(
            severity="medium",
            cve="CVE-2025-67586",
            version=version,
            reason=f"Highlight and Share version {version} <= 5.2.0 detected",
        )
        return True
