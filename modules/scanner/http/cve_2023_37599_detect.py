#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue in issabel-pbx v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Issabel PBX 4.0.0-6 - Directory Listing Detection',
        'description': 'An issue in issabel-pbx v.4.0.0-6 allows a remote attacker to obtain sensitive information via the modules directory',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'issabel', 'issabel-pbx', 'directory-listing', 'vuln'],
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
        'references': ['https://github.com/sahiloj/CVE-2023-37599', 'https://nvd.nist.gov/vuln/detail/CVE-2023-37599'],
        'cve': 'CVE-2023-37599',
    }

    def run(self):
        r = self.http_request(method="GET", path='/modules/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Index of /modules', 'issabel', 'asterisk_', 'billing_',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Issabel PBX 4.0.0-6 - Directory Listing detected",
                path='/modules/',
            )
            return True
        return False

