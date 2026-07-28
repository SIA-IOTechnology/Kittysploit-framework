#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ScadaBR is an open-source SCADA system based on Mango Automation, widely used in Brazil and Latin America for ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ScadaBR - Login Panel Detection',
        'description': 'ScadaBR is an open-source SCADA system based on Mango Automation, widely used in Brazil and Latin America for industrial monitoring. The "powered by Mango" tagline in the title is a unique identifier. Instances are often internet-facing without authentication controls.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'scada', 'ics', 'scadabr', 'mango', 'open-source', 'latin-america'],
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
        'references': ['https://www.scadabr.com.br/', 'https://github.com/ScadaBR/ScadaBR'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            '<title>ScadaBR</title>',
            'ScadaBR Software',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="ScadaBR - Login Panel detected",
                path='/',
            )
            return True
        return False

