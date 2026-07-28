#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""H2 Console Web login panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'H2 Console Web Login Panel - Detect',
        'description': 'H2 Console Web login panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'h2', 'console', 'h2database'],
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
            'https://mp.weixin.qq.com/s/Yn5U8WHGJZbTJsxwUU3UiQ',
            'https://jfrog.com/blog/the-jndi-strikes-back-unauthenticated-rce-in-h2-database-console',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/h2-console/login.jsp', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        markers = (
            '<title>h2 console</title>',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="H2 Console Web Login Panel detected",
                path='/h2-console/login.jsp',
            )
            return True
        return False

