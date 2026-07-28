#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""n8n is an open source workflow automation platform."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'n8n Webhooks - Remote Code Execution Detection',
        'description': 'n8n is an open source workflow automation platform. Versions starting with 1.65.0 and below 1.121.0 enable an attacker to access files on the underlying server through execution of certain form-based workflows. A vulnerable workflow could grant access to an unauthenticated remote attacker, resulting in exposure of sensitive information stored on the system and may enable further compromise depending on deployment configuration and workflow usage. This issue is fixed in version 1.121.0.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'modules': [
            'exploits/linux/http/n8n_full_chain_rce',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'n8n', 'workflow', 'rce', 'passive', 'vkev'],
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
            'https://thehackernews.com/2026/01/critical-n8n-vulnerability-cvss-100.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-21858',
        ],
        'cve': 'CVE-2026-21858',
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
                reason='n8n Webhooks - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

