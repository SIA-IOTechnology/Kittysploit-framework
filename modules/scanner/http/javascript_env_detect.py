#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple common JavaScript environment configuration files were detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JavaScript Environment Configuration - Detect',
        'description': 'Multiple common JavaScript environment configuration files were detected.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'javascript', 'config', 'vuln'],
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
        for path in ('/env.js', '/env.development.js', '/env.production.js', '/env.test.js', '/env.dev.js', '/env.prod.js', '/__ENV.js', '/env-config.js'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            body_any = ('application/javascript', 'module.exports', 'const audience', 'const domain', 'node_env', 'log_level', 'token', 'key', 'password', 'version', 'window.__env =', 'bootstrap', 'jquery', 'css transition support', 'is_ad_blocked',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='low',
                    reason="JavaScript Environment Configuration detected",
                    path=path,
                )
                return True
        return False

