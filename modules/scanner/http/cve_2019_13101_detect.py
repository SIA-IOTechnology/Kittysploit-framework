#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-600M 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-600M - Authentication Bypass Detection',
        'description': 'D-Link DIR-600M 3.02, 3.03, 3.04, and 3.06 devices can be accessed directly without authentication and lead to disclosure of information about the WAN, which can then be leveraged by an attacker to modify the data fields of the page.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2019', 'cve', 'packetstorm', 'edb', 'dlink', 'router', 'iot', 'vkev', 'vuln'],
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
            'https://github.com/d0x0/D-Link-DIR-600M',
            'https://www.exploit-db.com/exploits/47250',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-13101',
            'https://us.dlink.com/en/security-advisory',
            'http://packetstormsecurity.com/files/153994/D-Link-DIR-600M-Wireless-N-150-Home-Router-Access-Bypass.html',
        ],
        'cve': 'CVE-2019-13101',
    }

    def run(self):
        path = '/wan.htm'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Origin': '{{BaseURL}}'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/PPPoE/',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='D-Link DIR-600M - Authentication Bypass detected', path=path)
            return True
        return False

