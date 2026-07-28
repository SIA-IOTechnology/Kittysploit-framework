#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PhotoPrism instance is running in public mode with authentication disabled (PHOTOPRISM_AUTH_MODE=public), expo."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PhotoPrism - Unauthenticated Exposure Detection',
        'description': 'PhotoPrism instance is running in public mode with authentication disabled (PHOTOPRISM_AUTH_MODE=public), exposing all photos, albums, GPS locations, face recognition data, and server configuration to unauthenticated users.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'photoprism', 'exposure', 'unauth', 'misconfig'],
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
            'https://docs.photoprism.app/getting-started/config-options/#authentication',
            'https://docs.photoprism.app/getting-started/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/config', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('PhotoPrism', '"public":true', '"authMode":"public"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="PhotoPrism - Unauthenticated Exposure detected",
                path='/api/v1/config',
            )
            return True
        return False

