#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed bash configuration on web servers that could have contained sensitive information such as cre."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Bash Configuration - Exposure Detection',
        'description': 'Detected exposed bash configuration on web servers that could have contained sensitive information such as credentials, API keys, database connection strings, or internal paths.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'config', 'misconfig', 'bash'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
        for path in ('/.bashrc', '/.bash_profile', '/.profile', '/.zshrc'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('export', 'source', 'if [', 'then', 'echo', 'for', 'do', 'done', '<html', '<!DOCTYPE', '404', 'Not Found',)
            body_regexes = ('usr/(local|bin)/',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='low',
                    reason="Bash Configuration - Exposure detected",
                    path=path,
                )
                return True
        return False

