#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Janitza GridVis is an energy monitoring and management software platform by Janitza Electronics GmbH."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Janitza GridVis Energy Management - Detect',
        'description': 'Janitza GridVis is an energy monitoring and management software platform by Janitza Electronics GmbH. It provides real-time power quality analysis, energy data logging, and grid visualisation for industrial facilities.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'tech', 'janitza', 'ics', 'energy', 'scada'],
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
        'references': ['https://www.janitza.com/gridvis.html'],
    }

    def run(self):
        markers = (
            '<title>GridVis</title>',
            '/landingpage/img/favicon.ico',
            'gve-8janitza.energy.security',
        )
        for path in ('/landingpage', '/landingpage/'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")
            if any(m in body for m in markers):
                self.set_info(
                    severity='info',
                    reason="Janitza GridVis Energy Management detected",
                    path=path,
                )
                return True
        return False

