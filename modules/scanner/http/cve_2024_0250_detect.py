#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin is vulnerable to Open Redirect due to insufficient validation on the redirect oauth2callback."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Analytics Insights for Google Analytics 4 < 6.3 - Open Redirect Detection',
        'description': 'The plugin is vulnerable to Open Redirect due to insufficient validation on the redirect oauth2callback.php file. This makes it possible for unauthenticated attackers to redirect users to potentially malicious sites if they can successfully trick them into performing an action.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wpscan', 'redirect', 'wp', 'wp-plugin', 'wordpress', 'analytics-insights', 'vuln'],
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
            'https://wpscan.com/vulnerability/321b07d1-692f-48e9-a8e5-a15b38efa979/',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-0250',
        ],
        'cve': 'CVE-2024-0250',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/analytics-insights/tools/oauth2callback.php?state=https://oast.me/%3f&code=x', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Analytics Insights for Google Analytics 4 < 6.3 - Open Redirect detected",
                path='/wp-content/plugins/analytics-insights/tools/oauth2callback.php?state=https://oast.me/%3f&code=x',
            )
            return True
        return False

