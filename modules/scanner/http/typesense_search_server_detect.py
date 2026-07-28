#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Typesense was an open-source typo-tolerant search engine often self-hosted on TCP 8108."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Typesense Search Server - Detect',
        'description': 'Detected Typesense was an open-source typo-tolerant search engine often self-hosted on TCP 8108.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'tech', 'typesense', 'search'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://github.com/typesense/typesense', 'https://typesense.org/docs/latest/api/'],
    }

    def run(self):
        path = '/health'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        content_type = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        header_any = ('x-typesense',)
        ctype_any = ('application/json',)
        if (any(m in headers for m in header_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='info',
                reason='Typesense Search Server detected',
                path=path,
            )
            return True
        return False

