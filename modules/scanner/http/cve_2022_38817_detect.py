#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dapr Dashboard 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dapr Dashboard 0.1.0-0.10.0 - Improper Access Control Detection',
        'description': 'Dapr Dashboard 0.1.0 through 0.10.0 is susceptible to improper access control. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'dapr', 'dashboard', 'unauth', 'linuxfoundation', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://github.com/dapr/dashboard/issues/222',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-38817',
            'https://github.com/dapr/dashboard',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-38817',
            'https://github.com/Miraitowa70/POC-Notes',
        ],
        'cve': 'CVE-2022-38817',
    }

    def run(self):
        for path in ('/components/statestore', '/overview', '/controlplane'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<title>Dapr Dashboard</title>',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Dapr Dashboard 0.1.0-0.10.0 - Improper Access Control detected",
                    path=path,
                )
                return True
        return False

