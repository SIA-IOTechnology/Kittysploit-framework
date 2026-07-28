#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Module identified that the affected host is running an instance of Jenkins in debug mode, as a result stack tr."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Detect Jenkins in Debug Mode with Stack Traces Enabled',
        'description': 'Module identified that the affected host is running an instance of Jenkins in debug mode, as a result stack traces are enabled.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'jenkins', 'hackerone', 'vuln'],
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
        'references': ['https://hackerone.com/reports/221833'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/adjuncts/3a890183/', allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        body_all = ('java.lang.StringIndexOutOfBoundsException', 'String index out of range',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Detect Jenkins in Debug Mode with Stack Traces Enabled detected",
                path='/adjuncts/3a890183/',
            )
            return True
        return False

