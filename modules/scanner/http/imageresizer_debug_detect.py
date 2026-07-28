#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The ImageResizer debug endpoint exposes sensitive server configuration and path information."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ImageResizer Debug - Information Exposure Detection',
        'description': 'The ImageResizer debug endpoint exposes sensitive server configuration and path information.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'exposure', 'debug', 'imageresizer', 'config'],
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
            'https://world.optimizely.com/blogs/Eric-Pettersson/Dates/2016/4/hide-resizer-debug-ashx-from-your-website/',
        ],
    }

    def run(self):
        for path in ('/resizer.debug.ashx', '/resizer.debug'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('ImageResizer.', 'Diagnostics', 'Configuration:', 'Registered plugins:',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="ImageResizer Debug - Information Exposure detected",
                    path=path,
                )
                return True
        return False

