#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Jolokia Detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.probe_guard import looks_like_jolokia_version, validate_json_probe


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jolokia Detection',
        'description': 'Detects Jolokia Detection.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'jolokia'],
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
    }

    def run(self):
        for path in ('/jolokia/version', '/actuator/jolokia/version'):
            data, _response = validate_json_probe(
                self.http_request,
                path,
                looks_like_jolokia_version,
            )
            if data:
                self.set_info(
                    severity='info',
                    reason="Jolokia detected",
                    path=path,
                )
                return True
        return False

