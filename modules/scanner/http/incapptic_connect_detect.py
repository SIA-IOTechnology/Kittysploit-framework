#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ivanti Incapptic Connect panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.osint.favicon_hash import shodan_mmh3


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ivanti Incapptic Connect Panel - Detect',
        'description': 'Ivanti Incapptic Connect panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'ivanti', 'incapptic-connect'],
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
        'references': ['https://www.ivanti.com/products/incapptic-connect'],
    }

    def run(self):
        for path in ('/', '/static/img/custom_icons/favicon.ico'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            body_any = ('incapptic',)
            mmh3_vals = ('-1067582922',)
            if (any(m in body for m in body_any)) and (shodan_mmh3(r.content or b"") in mmh3_vals):
                self.set_info(
                    severity='info',
                    reason="Ivanti Incapptic Connect Panel detected",
                    path=path,
                )
                return True
        return False

