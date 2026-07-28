#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Matrix servers based on ."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Matrix Server Detect',
        'description': 'Detects Matrix servers based on .well-known entries. See https://en.wikipedia.org/wiki/Matrix_(protocol)',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'matrix'],
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
            'https://spec.matrix.org/v1.3/server-server-api/#getwell-knownmatrixserver, https://spec.matrix.org/v1.3/client-server-api/#getwell-knownmatrixclient',
        ],
    }

    def run(self):
        for path in ('/.well-known/matrix/server', '/.well-known/matrix/client'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('"m\\.([a-z]+)":',)
            body_re_hit = any(re.search(rx, body, 0) for rx in body_regexes)
            if body_re_hit:
                self.set_info(
                    severity='info',
                    reason="Matrix Server detected",
                    path=path,
                )
                return True
        return False

