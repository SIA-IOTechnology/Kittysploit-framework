#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Jellyfin media server exposed user information via the public users API endpoint."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jellyfin Public Users - Exposure Detection',
        'description': 'The Jellyfin media server exposed user information via the public users API endpoint. This endpoint could have leaked sensitive data including usernames, user IDs, server IDs, administrator status, password configuration, login activity, and user policies without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'jellyfin', 'exposure', 'api', 'disclosure'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://github.com/jellyfin/jellyfin/issues/880', 'https://jellyfin.org/docs/'],
    }

    def run(self):
        for path in ('/Users/Public', '/jellyfin/Users/Public'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('"Name"', '"ServerId"', '"Id"', '"Policy"', '"Configuration"',)
            ctype_any = ('application/json',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='medium',
                    reason='Jellyfin Public Users - Exposure detected',
                    path=path,
                )
                return True
        return False

