#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unauth users can search Mbeans in Jolokia."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jolokia - Searching MBeans Detection',
        'description': 'Unauth users can search Mbeans in Jolokia.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'jolokia', 'springboot', 'mbean', 'tomcat', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://thinkloveshare.com/hacking/ssrf_to_rce_with_jolokia_and_mbeans/',
            'https://github.com/laluka/jolokia-exploitation-toolkit',
        ],
    }

    def run(self):
        for path in ('/jolokia/search/*:test=test', '/actuator/jolokia/search/*:test=test'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('"type":"search"', '"value":',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="Jolokia - Searching MBeans detected",
                    path=path,
                )
                return True
        return False

