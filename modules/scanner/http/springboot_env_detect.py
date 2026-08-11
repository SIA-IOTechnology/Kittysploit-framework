#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sensitive environment variables may not be masked."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.probe_guard import validate_spring_json_probe
from lib.scanner.http.response_validation import looks_like_spring_actuator_env


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Springboot Env Actuator - Detect',
        'description': 'Sensitive environment variables may not be masked',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'springboot', 'env', 'exposure', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
        matched_path, _response = validate_spring_json_probe(
            self.http_request,
            ('/env', '/actuator/env', '/actuator;/env;', '/message-api/actuator/env'),
            looks_like_spring_actuator_env,
        )
        if not matched_path:
            return False
        self.set_info(
            severity='low',
            reason="Springboot Env Actuator detected",
            path=matched_path,
        )
        return True

