#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Django configuration information was detected, which could reveal web application framework exceptions that co."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Django Config - Detect',
        'description': 'Django configuration information was detected, which could reveal web application framework exceptions that could indicate exploitation attempts.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'config', 'django', 'vuln'],
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
        'references': [
            'https://docs.djangoproject.com/en/1.11/ref/exceptions/',
            'https://docs.djangoproject.com/en/1.11/topics/logging/#django-security',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code not in (400, 500):
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('seeing this error because you have <code>DEBUG = True</code>', 'SuspiciousOperation', 'DisallowedHost', 'DisallowedModelAdminLookup', 'DisallowedModelAdminToField', 'DisallowedRedirect', 'InvalidSessionKey', 'RequestDataTooBig', 'SuspiciousFileOperation', 'SuspiciousMultipartForm', 'SuspiciousSession', 'TooManyFieldsSent', 'PermissionDenied',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='info',
                reason="Django Config detected",
                path='/',
            )
            return True
        return False

