#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects the presence of the SAP NetWeaver Process Integration / Composition Environment Tools page."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SAP NetWeaver Composition Environment Tools - Detect',
        'description': 'Detects the presence of the SAP NetWeaver Process Integration / Composition Environment Tools page',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'sap', 'netweaver', 'cet'],
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
            'https://help.sap.com/doc/saphelp_scm700_ehp02/7.0.2/en-US/f6/2a7cb018bc4b239ea5b7af675a18ef/content.htm?no_cache=true',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/rep/start/index.jsp', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = (
            'Composition Environment Tools',
        )
        body_hit = any(m in body for m in body_markers)
        if body_hit:
            self.set_info(
                severity='info',
                reason="SAP NetWeaver Composition Environment Tools detected",
                path='/rep/start/index.jsp',
            )
            return True
        return False

