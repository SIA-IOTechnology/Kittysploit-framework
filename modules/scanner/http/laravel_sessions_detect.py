#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected unauthenticated access to the Laravel session storage directory, allowing attackers to browse and dow."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Laravel Sessions Folder Exposure Detection',
        'description': 'Detected unauthenticated access to the Laravel session storage directory, allowing attackers to browse and download session files that may contain active authentication tokens, CSRF tokens, and serialized user data.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'laravel', 'exposure', 'misconfig', 'storage', 'session'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        for path in ('/storage/framework/sessions/', '/storage/sessions/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Index of', 'Parent Directory', '<title>Index of', 'Directory listing for',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Laravel Sessions Folder Exposure detected",
                    path=path,
                )
                return True
        return False

