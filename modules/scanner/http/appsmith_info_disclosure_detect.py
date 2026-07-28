#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Appsmith <= v1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Appsmith <= v1.97 - Information Disclosure Detection',
        'description': 'Appsmith <= v1.97 instance management API endpoints are accessible without authentication, allowing an attacker to obtain sensitive information such as license plan, instance ID, authentication providers, feature flags, and configuration metadata via unauthenticated requests to specific API endpoints.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'appsmith', 'disclosure', 'exposure'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://github.com/appsmithorg/appsmith/security/advisories/GHSA-qvvc-prjx-f85j'],
    }

    def run(self):
        for path in ('/api/v1/consolidated-api/view', '/api/v1/users/features', '/api/v1/tenants/current'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('{"responseMeta":{', 'status":200,"success":true',)
            ctype_any = ('application/json',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='medium',
                    reason='Appsmith <= v1.97 - Information Disclosure detected',
                    path=path,
                )
                return True
        return False

