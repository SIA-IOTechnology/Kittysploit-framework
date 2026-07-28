#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected whether the WPS Hide Login plugin’s /classes/ directory was exposed with directory listing enabled du."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress WPS Hide Login - Error Log Disclosure Detection',
        'description': 'Detected whether the WPS Hide Login plugin’s /classes/ directory was exposed with directory listing enabled due to server misconfiguration, potentially disclosing PHP error logs or source code.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'wordpress', 'wp', 'wp-plugin', 'wps-hide-login', 'log'],
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
        'references': ['https://wordpress.org/plugins/wps-hide-login/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/wps-hide-login/classes/error_log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('PHP Fatal error:', 'PHP Warning:', 'PHP Parse error:', 'wp-content/plugins/wps-hide-login',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='low',
                reason="WordPress WPS Hide Login - Error Log Disclosure detected",
                path='/wp-content/plugins/wps-hide-login/classes/error_log',
            )
            return True
        return False

