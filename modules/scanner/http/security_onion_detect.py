#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security Onion is a free and open source Linux distribution for intrusion detection, security monitoring, and ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Security Onion Panel - Detect',
        'description': 'Security Onion is a free and open source Linux distribution for intrusion detection, security monitoring, and log management. It includes CyberChef, NetworkMiner, and many other security tools.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'security', 'onion', 'securityonionsolutions'],
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
            'https://securityonionsolutions.com/',
            'https://github.com/Security-Onion-Solutions/securityonion',
        ],
    }

    def run(self):
        markers = (
            '<title>Security Onion',
            'Login to Security Onion',
            'Security Onion Solutions',
        )
        for path in ('/', '/login/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")
            if any(m in body for m in markers):
                self.set_info(
                    severity='info',
                    reason="Security Onion Panel detected",
                    path=path,
                )
                return True
        return False

