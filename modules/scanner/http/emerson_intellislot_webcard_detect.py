#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emerson IntelliSlot Web Card interface panel was discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Emerson Network Power IntelliSlot Web Card - Exposure Detection',
        'description': 'Emerson IntelliSlot Web Card interface panel was discovered. This web interface provides remote monitoring and management capabilities for Emerson Network Power devices. Unauthorized access to this interface could potentially allow attackers to view sensitive information or control critical infrastructure equipment. Proper authentication and access controls should be implemented to secure this interface.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'iot', 'emerson', 'intellislot', 'misconfig', 'exposure'],
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
        'references': ['https://www.vertiv.com'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>Emerson Network Power IntelliSlot Web Card</title>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Emerson Network Power IntelliSlot Web Card - Exposure detected",
                path='/',
            )
            return True
        return False

