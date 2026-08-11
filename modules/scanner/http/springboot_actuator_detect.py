#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Detect Springboot Actuators."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.probe_guard import validate_spring_json_probe
from lib.scanner.http.response_validation import looks_like_spring_actuator_links


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Detect Springboot Actuators',
        'description': 'Detects Detect Springboot Actuators.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'springboot', 'actuator'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
        for path in ('/actuator', '/actuator%72'):
            matched_path, _response = validate_spring_json_probe(
                self.http_request,
                (path,),
                looks_like_spring_actuator_links,
            )
            if matched_path:
                self.set_info(
                    severity='info',
                    reason="Detect Springboot Actuators detected",
                    path=matched_path,
                )
                return True
        return False

