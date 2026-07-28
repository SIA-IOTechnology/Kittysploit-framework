#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The web application was built on the Laravel framework, with Laravel Terminal enabled and publicly accessible;."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Laravel Terminal - Exposed Detection',
        'description': 'The web application was built on the Laravel framework, with Laravel Terminal enabled and publicly accessible; this was detected in the production environment and led to disclosure of sensitive application information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'laravel', 'terminal', 'exposure', 'misconfig', 'rce'],
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
            'https://github.com/recca0120/laravel-terminal',
            'https://www.acunetix.com/vulnerabilities/web/laravel-terminal-open/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/asf/terminal', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Laravel Terminal', 'terminal.endpoint',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Laravel Terminal - Exposed detected",
                path='/asf/terminal',
            )
            return True
        return False

