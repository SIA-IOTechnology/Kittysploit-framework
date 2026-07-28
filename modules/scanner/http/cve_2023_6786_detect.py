#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin does not validate the api_url parameter before redirecting the user to its value, leading to an Ope."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Payment Gateway for Telcell < 2.0.4 - Open Redirect Detection',
        'description': 'The plugin does not validate the api_url parameter before redirecting the user to its value, leading to an Open Redirect issue',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'redirect', 'wp-plugin', 'wp', 'payment-gateway-for-telcell', 'vuln'],
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
            'https://wpscan.com/vulnerability/f3e64947-3138-4ec4-86c4-27b5d6a5c9c2/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-6786',
        ],
        'cve': 'CVE-2023-6786',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin.php?page=wc-settings&action=redirect_telcell_form&api_url=https://oast.me', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Payment Gateway for Telcell < 2.0.4 - Open Redirect detected",
                path='/wp-admin/admin.php?page=wc-settings&action=redirect_telcell_form&api_url=https://oast.me',
            )
            return True
        return False

