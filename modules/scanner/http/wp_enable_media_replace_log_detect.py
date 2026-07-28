#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WordPress plugin "Enable Media Replace" (enable-media-replace) bundles a ShortPixel-based logger that writ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin Enable Media Replace - Log File Exposure Detection',
        'description': 'The WordPress plugin "Enable Media Replace" (enable-media-replace) bundles a ShortPixel-based logger that writes a plugin-specific log file into the WordPress uploads directory, typically as `wp-content/uploads/EnableMediaReplace.log`.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'wordpress', 'wp', 'wp-plugin', 'enable-media-replace', 'log'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://wordpress.org/plugins/enable-media-replace/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/uploads/EnableMediaReplace.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Deprecated', 'enable-media-replace',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress Plugin Enable Media Replace - Log File Exposure detected",
                path='/wp-content/uploads/EnableMediaReplace.log',
            )
            return True
        return False

