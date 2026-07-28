#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Flask Debug Toolbar was exposed in production, potentially leaking sensitive application information,."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Flask Debug Toolbar - Exposure Detection',
        'description': 'Detected Flask Debug Toolbar was exposed in production, potentially leaking sensitive application information, SQL queries, request data, and configuration details.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'flask', 'python', 'debug', 'toolbar', 'exposure', 'misconfig'],
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
            'https://flask-debugtoolbar.readthedocs.io/',
            'https://github.com/flask-debugtoolbar/flask-debugtoolbar',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('flDebugToolbar', 'flDebugPanelList', '/_debug_toolbar/', 'flDebugVersionPanel', 'DEBUG_TOOLBAR_STATIC_PATH',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Flask Debug Toolbar - Exposure detected",
                path='/',
            )
            return True
        return False

