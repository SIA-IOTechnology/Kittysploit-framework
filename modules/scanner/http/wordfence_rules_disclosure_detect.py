#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Wordfence Security plugin for WordPress stores configuration files in the /wp-content/wflogs/ directory."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Wordfence - Rules File Disclosure Detection',
        'description': 'The Wordfence Security plugin for WordPress stores configuration files in the /wp-content/wflogs/ directory. These files may be accessible without authentication and can expose sensitive configuration data, firewall rules, attack logs, and internal paths.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'wordpress', 'wp-plugin', 'wordfence', 'rules', 'disclosure', 'exposure'],
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
            'https://wordpress.org/support/topic/files-created-in-wflogs-before-plugin-activated/',
            'https://forum.ait-pro.com/forums/topic/wordfence-firewall-wp-contentwflogsconfig-php-file-quarantined/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/wflogs/rules.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('wfWAFrule', '$this',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress Wordfence - Rules File Disclosure detected",
                path='/wp-content/wflogs/rules.php',
            )
            return True
        return False

