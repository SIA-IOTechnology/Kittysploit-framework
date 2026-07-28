#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress WP Maintenance Mode plugin is vulnerable to full path disclosure via direct access to plugin files."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress WP Maintenance Mode - Full Path Disclosure Detection',
        'description': 'WordPress WP Maintenance Mode plugin is vulnerable to full path disclosure via direct access to plugin files.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'wp', 'wordpress', 'wp-plugin', 'fpd', 'maintenance-mode', 'exposure'],
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
        'references': ['https://wordpress.org/plugins/wp-maintenance-mode/'],
    }

    def run(self):
        for path in ('/wp-content/plugins/wp-maintenance-mode/includes/classes/class-wp-maintenance-mode.php', '/wp-content/plugins/wp-maintenance-mode/includes/classes/class-wp-maintenance-mode-admin.php', '/wp-content/plugins/wp-maintenance-mode/views/maintenance.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Fatal error', 'wp-maintenance-mode', 'Uncaught Error:',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="WordPress WP Maintenance Mode - Full Path Disclosure detected",
                    path=path,
                )
                return True
        return False

