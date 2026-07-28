#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress OceanWP theme is vulnerable to full path disclosure via direct access to theme files."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress OceanWP - Full Path Disclosure Detection',
        'description': 'WordPress OceanWP theme is vulnerable to full path disclosure via direct access to theme files.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'wp', 'wordpress', 'wp-theme', 'fpd', 'oceanwp', 'exposure'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
        'references': ['https://wordpress.org/themes/oceanwp/'],
    }

    def run(self):
        for path in ('/wp-content/themes/oceanwp/inc/helpers.php', '/wp-content/themes/oceanwp/inc/customizer/customizer.php', '/wp-content/themes/oceanwp/inc/walker/menu-walker.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Fatal error', '/themes/oceanwp', 'Uncaught Error:',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="WordPress OceanWP - Full Path Disclosure detected",
                    path=path,
                )
                return True
        return False

