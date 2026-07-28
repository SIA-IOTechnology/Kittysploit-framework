#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress theme twentyfifteen internal file system path of a WordPress installation is exposed or disclosed to."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Twenty Fifteen Theme - Full Path Disclosure Detection',
        'description': 'WordPress theme twentyfifteen internal file system path of a WordPress installation is exposed or disclosed to unauthorized users.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'debug', 'wordpress', 'fpd', 'vuln', 'twentyfifteen', 'wp-themes'],
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
        'references': ['https://wordpress.org/themes/twentyfifteen/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/themes/twentyfifteen/functions.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Call to undefined function', '/themes/twentyfifteen/',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="WordPress Twenty Fifteen Theme - Full Path Disclosure detected",
                path='/wp-content/themes/twentyfifteen/functions.php',
            )
            return True
        return False

