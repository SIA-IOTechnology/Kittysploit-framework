#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Plugin SG Optimizer Plugin files are publicly accessible without ABSPATH protection, exposing sensit."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin SG Optimizer - Full Path Disclosure Detection',
        'description': 'WordPress Plugin SG Optimizer Plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'debug', 'wordpress', 'fpd', 'vuln', 'sg-cachepress', 'wp-plugin'],
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
        'references': ['https://wordpress.org/plugins/sg-cachepress/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/sg-cachepress/core/File_Cacher/File_Cacher.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('plugins/sg-cachepress',)
        body_all = ('Fatal error', 'Uncaught Error:',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="WordPress Plugin SG Optimizer - Full Path Disclosure detected",
                path='/wp-content/plugins/sg-cachepress/core/File_Cacher/File_Cacher.php',
            )
            return True
        return False

