#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Ghost CMS installation setup wizard accessible without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ghost CMS Installation Setup - Exposure Detection',
        'description': 'Detected Ghost CMS installation setup wizard accessible without authentication. An unauthenticated remote attacker can navigate to /ghost/#/setup and complete the installation to gain full owner-level administrative control of the site.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'ghost', 'cms', 'exposure', 'setup', 'takeover', 'unauth'],
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
        'references': [
            'https://ghost.org/docs/install/',
            'https://ghost.org/docs/config/',
            'https://github.com/TryGhost/Ghost',
        ],
    }

    def run(self):
        for path in ('/ghost/api/admin/authentication/setup/', '/ghost/api/v3/admin/authentication/setup/'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('application/json',)
            body_all = ('false',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Ghost CMS Installation Setup - Exposure detected",
                    path=path,
                )
                return True
        return False

