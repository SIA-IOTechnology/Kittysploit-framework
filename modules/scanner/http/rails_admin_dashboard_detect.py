#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected RailsAdmin dashboard was exposed without proper authentication, allowing unauthorized access to data ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RailsAdmin Dashboard Exposure Detection',
        'description': 'Detected RailsAdmin dashboard was exposed without proper authentication, allowing unauthorized access to data management interface.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'panel', 'rails', 'admin', 'exposure', 'misconfig'],
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
        'references': ['https://github.com/railsadminteam/rails_admin'],
    }

    def run(self):
        for path in ('/admin', '/rails_admin'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Sign in', 'Log in', 'login_form', 'devise',)
            body_all = ('Settings</a>', 'rails_admin_sidebar', 'rails_admin_content',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="RailsAdmin Dashboard Exposure detected",
                    path=path,
                )
                return True
        return False

