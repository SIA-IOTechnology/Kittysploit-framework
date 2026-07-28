#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wordpress internal file system path of a WordPress installation is exposed or disclosed to unauthorized users."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wordpress - Path Disclosure Detection',
        'description': 'Wordpress internal file system path of a WordPress installation is exposed or disclosed to unauthorized users.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'vulnerability', 'debug', 'wordpress', 'fpd', 'vuln'],
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
            'https://make.wordpress.org/core/handbook/testing/reporting-security-vulnerabilities/#why-are-there-path-disclosures-when-directly-loading-certain-files',
            'https://core.trac.wordpress.org/ticket/38317',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-includes/rss-functions.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Call to undefined function _deprecated_file()',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='info',
                reason="Wordpress - Path Disclosure detected",
                path='/wp-includes/rss-functions.php',
            )
            return True
        return False

