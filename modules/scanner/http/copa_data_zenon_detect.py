#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Copa-Data zenon is an industrial automation platform used in manufacturing, energy, and infrastructure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Copa-Data zenon - Login Panel Detection',
        'description': 'Copa-Data zenon is an industrial automation platform used in manufacturing, energy, and infrastructure. The zenon Web Server and Smart Server expose a browser-based HMI interface for remote monitoring and control of SCADA processes.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'scada', 'hmi', 'ics', 'copa-data', 'zenon'],
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
                'confidence_min': {
                },
                'confidence_min_any': {
                },
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
                'option_bindings': {
                },
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://www.copadata.com/en/products/zenon-software-platform/zenon-supervisor/',
            'https://www.copadata.com/en/support-services/knowledge-base-documents/zenon-web-server/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            'COPA-DATA',
            'zenon',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="Copa-Data zenon - Login Panel detected",
                path='/',
            )
            return True
        return False

