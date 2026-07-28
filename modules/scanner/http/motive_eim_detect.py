#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposed Motive eSIM Secure Connect (EIM) panels used for managing eSIM/iSIM provisioning."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Motive eSIM Secure Connect Panel - Exposure Detection',
        'description': 'Detects exposed Motive eSIM Secure Connect (EIM) panels used for managing eSIM/iSIM provisioning. Public access to these interfaces may allow attackers to view or interact with sensitive operations such as EID management and bulk provisioning, leading to information disclosure or unauthorized control over IoT/mobile connectivity services.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'panel', 'motive', 'eim', 'esim', 'iot'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
        'references': ['https://motive.com/eim'],
    }

    def run(self):
        markers = (
            '<title>EIM</title>',
        )
        for path in ('/eIMConfiguration', '/eid-management', '/eid-management-new', '/bulk-profile-operation'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")
            if any(m in body for m in markers):
                self.set_info(
                    severity='high',
                    reason="Motive eSIM Secure Connect Panel - Exposure detected",
                    path=path,
                )
                return True
        return False

