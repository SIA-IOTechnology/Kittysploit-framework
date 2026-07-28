#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The URL Shortify plugin for WordPress is vulnerable to Open Redirect in all versions up to, and including, 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'URL Shortify <= 1.12.1 - Open Redirect Detection',
        'description': "The URL Shortify plugin for WordPress is vulnerable to Open Redirect in all versions up to, and including, 1.12.1 due to insufficient validation on the 'redirect_to' parameter in the promotional dismissal handler. This makes it possible for unauthenticated attackers to redirect users to potentially malicious sites via a crafted link.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'wordpress', 'wp', 'wp-plugin', 'redirect', 'url-shortify', 'unauth', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/url-shortify/url-shortify-1121-unauthenticated-open-redirect-via-redirect-to-parameter',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-1277',
        ],
        'cve': 'CVE-2026-1277',
    }

    def run(self):
        for path in ('/wp-admin/admin-ajax.php?action=heartbeat&kc_us_dismiss_admin_notice=1&option_name=bfcm_2025_offer&redirect_to=https://interact.sh', '/wp-admin/admin-ajax.php?action=heartbeat&kc_us_dismiss_admin_notice=1&option_name=welcome_offer&redirect_to=https://interact.sh'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
            if (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='medium',
                    reason="URL Shortify <= 1.12.1 - Open Redirect detected",
                    path=path,
                )
                return True
        return False

