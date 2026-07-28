#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Chroma DB API endpoints were accessible and exposed collection metadata, enabling enumeration of collections u."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chroma DB - Information Disclosure Detection',
        'description': 'Chroma DB API endpoints were accessible and exposed collection metadata, enabling enumeration of collections under the default tenant and database, potentially leading to sensitive vector data disclosure.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'api', 'info-leak', 'unauth'],
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
        'references': [
            'https://www.trychroma.com/security',
            'https://github.com/shaybentk/chroma-db-unauthorized-info-disclosure',
        ],
    }

    def run(self):
        for path in ('/api/v1/collections?tenant=default_tenant&database=default_database', '/api/v2/tenants/default_tenant/databases/default_database/collections'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('"sync_threshold":', '"log_position"',)
            ctype_any = ('application/json',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='high',
                    reason='Chroma DB - Information Disclosure detected',
                    path=path,
                )
                return True
        return False

