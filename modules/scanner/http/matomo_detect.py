#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""google analytics alternative that protects your data and your customers privacy."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Matomo Panel - Detect',
        'description': 'google analytics alternative that protects your data and your customers privacy.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'matomo', 'login'],
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
        'references': ['https://matomo.org/', 'https://matomo.org/faq/on-premise/installing-matomo/#getting-started'],
    }

    def run(self):
        markers = (
            'sign in - matomo',
            'content="matomo',
            'title="matomo',
        )
        for path in ('/', '/index.php', '/plugins/CoreHome/images/favicon.png'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            if any(m in body for m in markers):
                self.set_info(
                    severity='info',
                    reason="Matomo Panel detected",
                    path=path,
                )
                return True
        return False

