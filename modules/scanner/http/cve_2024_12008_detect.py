#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin is vulnerable to Information Exposure through the publicly exposed debug log file."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'W3 Total Cache < 2.8.2 - Log File Exposure Detection',
        'description': 'The plugin is vulnerable to Information Exposure through the publicly exposed debug log file. This makes it possible for unauthenticated attackers to view potentially sensitive information in the exposed log file. For example, the log file may contain nonce values that can be used in further CSRF attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wordpress', 'wp', 'wp-plugin', 'w3-total-cache', 'exposure', 'logs'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/1685ca58-1622-433b-b561-304cb9d1bc56/',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/8292f23c-fb17-4082-9788-f643d1bb097e',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-12008',
        ],
        'cve': 'CVE-2024-12008',
    }

    def run(self):
        for path in ('/wp-content/cache/log/000000/pagecache.log', '/wp-content/cache/log/000000/minify.log'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('[/] [-]',)
            body_regexes = ('\\\\[[A-Za-z]{3}, \\\\d{2} [A-Za-z]{3} \\\\d{4} \\\\d{2}:\\\\d{2}:\\\\d{2} [+-]\\\\d{4}\\\\]',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason='W3 Total Cache < 2.8.2 - Log File Exposure detected',
                    path=path,
                )
                return True
        return False

