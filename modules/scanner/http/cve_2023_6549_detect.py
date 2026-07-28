#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The vulnerability would enable an attacker to remotely obtain sensitive information from a NetScaler appliance."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Citrix Netscaler ADC & Gateway - Out-Of-Bounds Memory Read Detection',
        'description': 'The vulnerability would enable an attacker to remotely obtain sensitive information from a NetScaler appliance configured as a Gateway or AAA virtual server via a very commonly connected Web interface, and without requiring authentication. This bug is nearly identical to the Citrix Bleed vulnerability (CVE-2023-4966), except it is less likely to return highly sensitive information to an attacker.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'citrix', 'netscaller', 'gateway', 'oob', 'kev', 'vkev', 'vuln'],
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
            'https://bishopfox.com/blog/netscaler-adc-and-gateway-advisory',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-6549',
        ],
        'cve': 'CVE-2023-6549',
    }

    def run(self):
        path = '/nf/auth/startwebview.do'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('/nf/auth/webview/done', 'AuthenticationRequirements',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Citrix Netscaler ADC & Gateway - Out-Of-Bounds Memory Read detected', path=path)
            return True
        return False

