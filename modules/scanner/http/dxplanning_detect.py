#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DXPlanning was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DXPlanning Panel - Detect',
        'description': 'DXPlanning was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'dxplanning', 'login'],
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
        'references': [
            'https://www.dedalus.com/fr/wp-content/uploads/sites/13/2022/05/Catalogue-formations-DxCare-2022.pdf',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/DxPlanning/WebBooking/Version', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_markers = (
            'dxplanning/webbooking/',
            'webbooking</title>',
        )
        if any(m in body for m in body_markers):
            self.set_info(
                severity='info',
                reason="DXPlanning Panel detected",
                path='/DxPlanning/WebBooking/Version',
            )
            return True
        return False

