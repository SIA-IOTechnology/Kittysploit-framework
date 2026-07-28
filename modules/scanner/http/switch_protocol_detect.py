#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Switching Protocol Detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Switching Protocol Detection',
        'description': 'Detects Switching Protocol Detection.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'protocol', 'switching', 'tech', 'websocket', 'h2c'],
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
        r = self.http_request(
            method="GET",
            path='/',
            allow_redirects=False,
            headers={
                "Connection": "Upgrade",
                "Upgrade": "websocket",
            },
        )
        # Real switching-protocols response is HTTP 101, not a normal 200 homepage.
        if not r or r.status_code != 101:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        if "upgrade" not in headers:
            return False
        self.set_info(
            severity='info',
            reason="Switching Protocol (HTTP 101) detected",
            path='/',
        )
        return True

