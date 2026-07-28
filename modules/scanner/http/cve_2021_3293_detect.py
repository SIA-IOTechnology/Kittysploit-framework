#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""emlog v5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'emlog 5.3.1 Path Disclosure Detection',
        'description': 'emlog v5.3.1 is susceptible to full path disclosure via t/index.php, which allows an attacker to see the path to the webroot/file.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'emlog', 'fpd', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://github.com/emlog/emlog/issues/62',
            'https://github.com/thinkgad/Bugs/blob/main/emlog%20v5.3.1%20has%20Full%20Path%20Disclosure%20vulnerability.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3293',
            'https://github.com/Z0fhack/Goby_POC',
            'https://github.com/20142995/Goby',
        ],
        'cve': 'CVE-2021-3293',
    }

    def run(self):
        path = '/t/index.php?action[]=aaaa'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<b>Warning</b>', 'on line', 'expects parameter',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='emlog 5.3.1 Path Disclosure detected', path=path)
            return True
        return False

