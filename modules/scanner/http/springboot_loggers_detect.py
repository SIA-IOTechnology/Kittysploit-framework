#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Springboot Loggers is exposed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.probe_guard import looks_like_spring_loggers, validate_spring_json_probe


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Springboot Loggers - Exposure Detection',
        'description': 'Springboot Loggers is exposed.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'springboot', 'exposure', 'misconfig', 'vuln'],
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
                'suggested_followups': [],
            },
        },
    }

    def run(self):
        matched_path, _response = validate_spring_json_probe(
            self.http_request,
            ('/loggers', '/actuator/loggers'),
            looks_like_spring_loggers,
        )
        if not matched_path:
            return False
        self.set_info(
            severity='low',
            reason='Springboot Loggers - Exposure detected',
            path=matched_path,
        )
        return True

