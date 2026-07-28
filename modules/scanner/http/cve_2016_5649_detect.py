#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETGEAR DGN2200 / DGND3700 is susceptible to a vulnerability within the page 'BSW_cxttongr."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NETGEAR DGN2200 / DGND3700 - Admin Password Disclosure Detection',
        'description': "NETGEAR DGN2200 / DGND3700 is susceptible to a vulnerability within the page 'BSW_cxttongr.htm' which can allow a remote attacker to access this page without any authentication. The attacker can then use this password to gain administrator access of the targeted router's web interface.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2016', 'cve', 'iot', 'netgear', 'router', 'packetstorm', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2016-5649',
            'https://packetstormsecurity.com/files/140342/Netgear-DGN2200-DGND3700-WNDR4500-Information-Disclosure.html',
            'http://packetstormsecurity.com/files/152675/Netgear-DGN2200-DGND3700-Admin-Password-Disclosure.html',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2016-5649',
    }

    def run(self):
        path = '/BSW_cxttongr.htm'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>Smart Wizard Result</title>',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='NETGEAR DGN2200 / DGND3700 - Admin Password Disclosure detected', path=path)
            return True
        return False

