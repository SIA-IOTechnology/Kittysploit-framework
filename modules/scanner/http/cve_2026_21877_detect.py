#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""n8n versions >= 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'n8n >= 0.123.0 and < 1.121.3 - Remote Code Execution Detection',
        'description': 'n8n versions >= 0.123.0 and < 1.121.3 contain a critical authenticated remote code execution vulnerability via arbitrary file write. An authenticated user can exploit the Git node to overwrite critical files and execute untrusted code on the n8n server, potentially leading to full system compromise. The vulnerability affects both self-hosted and n8n Cloud instances.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'n8n', 'workflow', 'rce', 'authenticated', 'passive'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/n8n-io/n8n/security/advisories/GHSA-v364-rw7m-3263',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-21877',
        ],
        'cve': 'CVE-2026-21877',
    }

    def run(self):
        path = '/signin'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('<title>n8n.io',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='n8n >= 0.123.0 and < 1.121.3 - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

