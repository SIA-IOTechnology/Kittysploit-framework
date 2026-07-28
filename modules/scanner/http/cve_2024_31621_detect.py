#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The flowise version <= 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Flowise 1.6.5 - Authentication Bypass Detection',
        'description': 'The flowise version <= 1.6.5 is vulnerable to authentication bypass vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'auth-bypass', 'flowise', 'vuln', 'ai'],
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
            'https://www.exploit-db.com/exploits/52001',
            'https://github.com/FlowiseAI/Flowise/releases',
            'https://flowiseai.com/',
        ],
        'cve': 'CVE-2024-31621',
    }

    def run(self):
        r = self.http_request(method="GET", path='/API/V1/credentials', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"credentialName":', '"updatedDate":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Flowise 1.6.5 - Authentication Bypass detected",
                path='/API/V1/credentials',
            )
            return True
        return False

