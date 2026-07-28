#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Jakefile build configuration was found to be exposed, potentially having contained sensitive informat."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jakefile Build Configuration - Disclosure Detection',
        'description': 'Detected Jakefile build configuration was found to be exposed, potentially having contained sensitive information including database credentials, API keys, and server configurations.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'devops', 'jakefile', 'nodejs', 'config'],
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
        'references': ['https://jakejs.com/', 'https://github.com/jakejs/jake'],
    }

    def run(self):
        for path in ('/Jakefile', '/Jakefile.js'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<!DOCTYPE', '<html', '<HTML', 'desc(', 'jake.', 'namespace(', 'task(',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='info',
                    reason="Jakefile Build Configuration - Disclosure detected",
                    path=path,
                )
                return True
        return False

