#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flowise is a drag & drop user interface to build a customized large language model flow."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Flowise - NVIDIA NIM Endpoints Missing Authentication Detection',
        'description': 'Flowise is a drag & drop user interface to build a customized large language model flow. Prior to version 3.0.13, the NVIDIA NIM router (/api/v1/nvidia-nim/*) is whitelisted in the global authentication middleware, allowing unauthenticated access to privileged container management and token generation endpoints.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'flowise', 'nvidia', 'nim', 'unauth', 'auth-bypass', 'token-leak'],
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
            'https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-5f53-522j-j454',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-30824',
            'https://github.com/FlowiseAI/Flowise',
        ],
        'cve': 'CVE-2026-30824',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/nvidia-nim/get-token', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('access_token', 'token_type',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Flowise - NVIDIA NIM Endpoints Missing Authentication detected",
                path='/api/v1/nvidia-nim/get-token',
            )
            return True
        return False

