#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects WordPress ThemeMarkers DB Migration File."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress ThemeMarkers DB Migration File Detection',
        'description': 'Detects WordPress ThemeMarkers DB Migration File.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'backup', 'vuln'],
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
    }

    def run(self):
        path = '/wp-content/uploads/tmm_db_migrate/tmm_db_migrate.zip'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/zip',)
        body_regexes = ('[a-z0-9_]+.dat',)
        raw = r.content or b""
        binary_hex = ('504B0304',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)) and (any(bytes.fromhex(h) in raw for h in binary_hex)):
            self.set_info(
                severity='info',
                reason='WordPress ThemeMarkers DB Migration File detected',
                path=path,
            )
            return True
        return False

