#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposed auth."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Bitbucket OAuth Credentials Exposure Detection',
        'description': 'Detects exposed auth.json files containing Bitbucket OAuth credentials',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'bitbucket', 'oauth', 'credentials', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
    }

    def run(self):
        for path in ('/auth.json', '/.auth.json', '/config/auth.json', '/configs/auth.json', '/configuration/auth.json', '/api/auth.json', '/app/auth.json', '/assets/auth.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            body_any = ('bitbucket-oauth', 'bitbucket',)
            body_regexes = ('(?i)consumer[-_]*secret', '(?i)consumer[-_]*key',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, body, re.I) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Bitbucket OAuth Credentials Exposure detected",
                    path=path,
                )
                return True
        return False

