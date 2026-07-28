#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Keycloak admin console configuration was exposing realm name, client ID, SSL requirements, and authen."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Keycloak Admin Console Configuration Disclosure Detection',
        'description': 'Detected Keycloak admin console configuration was exposing realm name, client ID, SSL requirements, and authentication server URL enabling reconnaissance and targeted authentication attacks.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'keycloak', 'config', 'disclosure'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
        'references': [
            'https://www.keycloak.org/docs/latest/server_admin/index.html',
            'https://www.keycloak.org/docs/latest/securing_apps/index.html',
        ],
    }

    def run(self):
        for path in ('/admin/master/console/config', '/admin/main/console/config', '/auth/admin/master/console/config', '/auth/admin/main/console/config'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('"realm":', '"resource":', '"auth-server-url":',)
            ctype_any = ('application/json',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='low',
                    reason='Keycloak Admin Console Configuration Disclosure detected',
                    path=path,
                )
                return True
        return False

