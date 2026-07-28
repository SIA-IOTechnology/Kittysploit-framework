#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected publicly accessible AsyncAPI specification files (YAML/JSON), which might have exposed message channe."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AsyncAPI Spec Inventory Detection',
        'description': 'Detected publicly accessible AsyncAPI specification files (YAML/JSON), which might have exposed message channels, server endpoints, and security schemes.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'asyncapi', 'api'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
            'https://www.asyncapi.com/docs/reference/specification',
            'https://raw.githubusercontent.com/asyncapi/spec/v2.6.0/examples/streetlights-kafka.yml',
        ],
    }

    def run(self):
        for path in ('/', '/asyncapi', '/asyncapi.yaml', '/asyncapi.yml', '/asyncapi.json', '/api/asyncapi', '/api/docs/asyncapi', '/docs/asyncapi'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('(?i)\\basyncapi\\s*:\\s*[\'"]?[0-9.]+', '(?i)"asyncapi"\\s*:\\s*"([0-9.]+)"',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='info',
                    reason="AsyncAPI Spec Inventory detected",
                    path=path,
                )
                return True
        return False

