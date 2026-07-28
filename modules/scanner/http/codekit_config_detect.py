#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed CodeKit configuration files that may have revealed sensitive project information, including f."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CodeKit Configuration Exposure Detection',
        'description': 'Detected exposed CodeKit configuration files that may have revealed sensitive project information, including file paths, build settings, hooks, and project structure.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'codekit', 'config'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://codekitapp.com/', 'https://owasp.org/www-project-web-security-testing-guide/'],
    }

    def run(self):
        for path in ('/config.codekit3', '/config.codekit', '/assets/js/config.codekit3'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('This is a CodeKit 3 project config file', 'creatorBuild', 'uuidString',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="CodeKit Configuration Exposure detected",
                    path=path,
                )
                return True
        return False

