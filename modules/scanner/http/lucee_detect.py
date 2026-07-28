#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lucee admin login panels were detected in both Web and Server tabs."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Lucee Web and Lucee Server Admin Login Panel - Detect',
        'description': 'Lucee admin login panels were detected in both Web and Server tabs.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'lucee'],
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
        markers = (
            '<title>Login - Lucee Web Administrator</title>',
            '<title>Login - Lucee Server Administrator</title>',
            'lucee-admin-search-input',
            'lucee-docs-search-input',
            'server-lucee-small.png.cfm',
        )
        for path in ('/lucee/admin/web.cfm', '/lucee/admin/server.cfm'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")
            if any(m in body for m in markers):
                self.set_info(
                    severity='info',
                    reason="Lucee Web and Lucee Server Admin Login Panel detected",
                    path=path,
                )
                return True
        return False

