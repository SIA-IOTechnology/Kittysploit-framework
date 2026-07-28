#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ngrok is a popular platform that provides secure tunnels to localhost, allowing users to expose a local web se."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ngrok Status Page Detection',
        'description': 'Ngrok is a popular platform that provides secure tunnels to localhost, allowing users to expose a local web server to the internet.The Ngrok status page is a web page that provides real-time information about the health and performance of the Ngrok service.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'ngrok', 'misconfig', 'status', 'vuln'],
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
        r = self.http_request(method="GET", path='/status', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>ngrok</title>', '<title>ngrok - Status</title>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='low',
                reason="Ngrok Status Page detected",
                path='/status',
            )
            return True
        return False

