#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Morningstar ProStar MPPT is a solar charge controller with a built-in web server providing live data monitorin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Morningstar ProStar MPPT Solar Charge Controller - Detect',
        'description': 'Morningstar ProStar MPPT is a solar charge controller with a built-in web server providing live data monitoring for off-grid and industrial solar installations. The exposed interface displays real-time array, battery, and load data without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'tech', 'morningstar', 'ics', 'solar', 'energy', 'scada'],
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
        'references': ['https://www.morningstarcorp.com/products/prostar-mppt/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            '<title>Prostar MPPT - Live Data</title>',
            'ProstarMPPTLive',
            'morningstarcorp.com',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="Morningstar ProStar MPPT Solar Charge Controller detected",
                path='/',
            )
            return True
        return False

