#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Shake Board digitizer receives, processes, and interprets the sensor data in real-time, allowing for the R."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Raspberry Shake Config Detection',
        'description': 'The Shake Board digitizer receives, processes, and interprets the sensor data in real-time, allowing for the Raspberry Pi computer to export the data for easy access. The data output can be displayed and analyzed using our own comprehensive set of web tools or any standard seismological software.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'iot', 'misconfig', 'unauth', 'raspberry'],
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
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Raspberry Shake Config',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Raspberry Shake Config detected",
                path='/',
            )
            return True
        return False

