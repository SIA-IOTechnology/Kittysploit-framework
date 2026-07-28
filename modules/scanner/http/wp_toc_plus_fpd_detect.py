#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Table of Contents Plus WordPress plugin is vulnerable to Full Path Disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin Table of Contents Plus - Full Path Disclosure Detection',
        'description': 'The Table of Contents Plus WordPress plugin is vulnerable to Full Path Disclosure. This vulnerability allows attackers to view the full server path by accessing certain files or triggering error conditions, which can aid in further attacks such as directory traversal or local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'wp', 'wordpress', 'wp-plugin', 'table-of-contents-plus', 'fpd', 'exposure'],
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
        'references': [
            'https://wordpress.org/plugins/table-of-contents-plus/',
            'https://wpscan.com/plugins/table-of-contents-plus/',
        ],
    }

    def run(self):
        for path in ('/wp-content/plugins/table-of-contents-plus/toc-plus.php', '/wp-content/plugins/table-of-contents-plus/toc.php', '/wp-content/plugins/table-of-contents-plus/includes/class-toc.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Fatal error', 'undefined function', 'table-of-contents-plus',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="WordPress Plugin Table of Contents Plus - Full Path Disclosure detected",
                    path=path,
                )
                return True
        return False

