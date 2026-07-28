#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The DD-WRT web interface was found exposed without proper access controls, potentially allowing unauthorized u."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DD-WRT Control Panel - Exposure Detection',
        'description': 'The DD-WRT web interface was found exposed without proper access controls, potentially allowing unauthorized users to view.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'dd-wrt', 'exposure', 'misconfig', 'vuln'],
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
        'references': ['https://wiki.dd-wrt.com/wiki/index.php/Web_interface', 'https://dd-wrt.com/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DD-WRT Control Panel', 'WAN IPv6',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="DD-WRT Control Panel - Exposure detected",
                path='/',
            )
            return True
        return False

