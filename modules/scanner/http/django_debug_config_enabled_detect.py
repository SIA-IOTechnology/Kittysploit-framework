#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Django debug configuration is enabled, which allows an attacker to obtain system configuration information suc."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Django Debug Configuration Enabled Detection',
        'description': 'Django debug configuration is enabled, which allows an attacker to obtain system configuration information such as paths or settings.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'django', 'debug', 'misconfig', 'vuln'],
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
    }

    def run(self):
        r = self.http_request(method="GET", path='/NON_EXISTING_PATH/', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        body_all = ('URLconf defined', 'Page not found', 'Django tried these URL patterns, in this order',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Django Debug Configuration Enabled detected",
                path='/NON_EXISTING_PATH/',
            )
            return True
        return False

