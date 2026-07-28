#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Versa Networks Detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.osint.favicon_hash import shodan_mmh3


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Versa Networks Detection',
        'description': 'Detects Versa Networks Detection.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'versa'],
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
        'references': ['https://versa-networks.com/products/components/'],
    }

    def run(self):
        for path in ('/favicon.ico', '/favicon.png', '/images/versalogo.png', '/images/versalogo2.png', '/common/images/Logo.png', '/versa/dist/images/versa-logo.png', '/versa/styles/img/versa-logo.png', '/versa/app/img/versa-logo.png'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            mmh3_vals = ('-1053531639', '-1086395444', '186362384', '2033952700', '-534530225',)
            if (shodan_mmh3(r.content or b"") in mmh3_vals):
                self.set_info(
                    severity='info',
                    reason="Versa Networks detected",
                    path=path,
                )
                return True
        return False

