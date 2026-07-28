#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open Access Management (OpenAM) is an access management solution."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenAM <= 16.0.5 - Pre-Auth RCE via jato.clientSession Deserialization Detection',
        'description': 'Open Access Management (OpenAM) is an access management solution. Prior to 16.0.6, OpenIdentityPlatform OpenAM is vulnerable to pre-authentication Remote Code Execution (RCE) via unsafe Java deserialization of the jato.clientSession HTTP parameter. This bypasses the WhitelistObjectInputStream mitigation that was applied to the jato.pageSession parameter after CVE-2021-35464. This vulnerability is fixed in 16.0.6.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'openam', 'deserialization', 'rce', 'jato', 'oast', 'oob'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://www.hacktron.ai/blog/openam-deserialization-pre-auth-rce',
            'https://github.com/OpenIdentityPlatform/OpenAM/security/advisories/GHSA-2cqq-rpvq-g5qj',
        ],
        'cve': 'CVE-2026-33439',
    }

    def run(self):
        r = self.http_request(method="GET", path='/openam/ui/PWResetUserValidation', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('OpenAM', 'tfUserAttr',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="OpenAM <= 16.0.5 - Pre-Auth RCE via jato.clientSession Deserialization detected",
                path='/openam/ui/PWResetUserValidation',
            )
            return True
        return False

