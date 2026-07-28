#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fortinet FortiSandbox login panel was discovered."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortinet FortiSandbox Panel - Detect',
        'description': 'Fortinet FortiSandbox login panel was discovered.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'fortinet', 'fortisandbox', 'tech', 'login'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://www.fortinet.com/products/sandbox/fortisandbox',
            'https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/FortiSandbox.pdf',
        ],
    }

    def run(self):
        for path in ('/', '/fsa/login', '/ng/login?returnUrl=%2F'):
            r = self.http_request(method='GET', path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
            body_any = ('<title>fortisandbox</title>', '<span>fortisandbox', 'fsa_login_logo', '/images/fsa_logo', 'fortisandbox',)
            header_regexes = ('Set-Cookie: FSA_SESSION_ID=',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, headers, re.I) for rx in header_regexes)):
                self.set_info(
                    severity='info',
                    reason='Fortinet FortiSandbox Panel detected',
                    path=path,
                )
                return True
        return False

