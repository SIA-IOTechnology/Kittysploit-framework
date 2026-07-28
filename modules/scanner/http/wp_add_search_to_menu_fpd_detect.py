#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Plugin Ivory Search plugin files are publicly accessible without ABSPATH protection, exposing sensit."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Ivory Search - Full Path Disclosure Detection',
        'description': 'WordPress Plugin Ivory Search plugin files are publicly accessible without ABSPATH protection, exposing sensitive server path information through PHP error messages when accessed directly.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'wp', 'wordpress', 'wp-plugin', 'fpd', 'add-search-to-menu', 'misconfig'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
        'references': ['https://wordpress.org/plugins/add-search-to-menu/'],
    }

    def run(self):
        for path in ('/wp-content/plugins/add-search-to-menu/includes/class-is-admin-public.php', '/wp-content/plugins/add-search-to-menu/includes/class-is-widget.php', '/wp-content/plugins/add-search-to-menu/includes/class-is-index-options.php', '/wp-content/plugins/add-search-to-menu/includes/class-is-index-manager.php', '/wp-content/plugins/add-search-to-menu/includes/class-is-customizer.php', '/wp-content/plugins/add-search-to-menu/includes/compatibility/class-is-tablepress-compat.php', '/wp-content/plugins/add-search-to-menu/admin/class-is-list-table.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('add-search-to-menu',)
            body_all = ('Fatal error', 'Uncaught Error', 'Warning:', 'failed to open stream',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="WordPress Ivory Search - Full Path Disclosure detected",
                    path=path,
                )
                return True
        return False

