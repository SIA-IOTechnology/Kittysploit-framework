#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Plugin WPML Version < 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin WPML Version < 4.6.1 Cross-Site Scripting Detection',
        'description': 'WordPress Plugin WPML Version < 4.6.1 is vulnerable to RXSS via wp_lang parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'wp', 'wordpress', 'wpml', 'wp-plugin', 'vuln'],
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
            'https://wpml.org/fr/changelog/2023/03/wpml-4-6-1-important-security-update/',
            'https://twitter.com/bug_vs_me/status/1652789903766200320',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-login.php?wp_lang=en_US%27', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('#039;"=', 'wpml_lang',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress Plugin WPML Version < 4.6.1 Cross-Site Scripting detected",
                path='/wp-login.php?wp_lang=en_US%27',
            )
            return True
        return False

