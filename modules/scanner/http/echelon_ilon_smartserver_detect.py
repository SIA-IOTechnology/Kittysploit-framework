#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Echelon (now Adesto/Dialog Semiconductor) i."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Echelon i.LON SmartServer - Login Panel Detection',
        'description': 'Echelon (now Adesto/Dialog Semiconductor) i.LON SmartServer is a LonWorks/IP-852 building automation controller used in HVAC, lighting, and energy management systems. The embedded web interface is frequently exposed on standard and non-standard ports.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'echelon', 'ilon', 'lonworks', 'scada', 'ics', 'ot', 'building-automation'],
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
        'references': ['https://www.echelon.com/products/ilon-smartserver/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            'i.LON SmartServer',
            'Echelon',
            'SmartServer',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="Echelon i.LON SmartServer - Login Panel detected",
                path='/',
            )
            return True
        return False

