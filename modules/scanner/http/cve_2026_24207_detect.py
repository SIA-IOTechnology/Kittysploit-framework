#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NVIDIA Triton Inference Server contains an authentication bypass vulnerability, letting attackers bypass authe."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NVIDIA Triton Inference Server <= 26.02 - Authentication Bypass Detection',
        'description': 'NVIDIA Triton Inference Server contains an authentication bypass vulnerability, letting attackers bypass authentication and potentially execute code, escalate privileges, tamper data, cause denial of service, or disclose information, exploit requires no special conditions.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'nvidia', 'triton', 'auth-bypass', 'rce', 'ml', 'ai'],
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
        'references': ['https://github.com/offseckit/CVE-2026-24207', 'https://offseckit.com/blog/cve-2026-24207'],
        'cve': 'CVE-2026-24207',
    }

    def run(self):
        r = self.http_request(method="GET", path='/models', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"models":[', 'This API is restricted', 'restricted',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="NVIDIA Triton Inference Server <= 26.02 - Authentication Bypass detected",
                path='/models',
            )
            return True
        return False

