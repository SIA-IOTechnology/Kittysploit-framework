#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Storm instance is exposed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.probe_guard import looks_like_apache_storm_summary, validate_json_probe


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Storm Unauth Detection',
        'description': 'Apache Storm instance is exposed.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'apache', 'unauth', 'misconfig', 'vuln'],
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
        'references': ['https://storm.apache.org/releases/current/STORM-UI-REST-API.html'],
    }

    def run(self):
        path = '/api/v1/cluster/summary'
        data, _response = validate_json_probe(
            self.http_request,
            path,
            looks_like_apache_storm_summary,
        )
        if not data:
            return False
        self.set_info(
            severity='medium',
            reason="Apache Storm Unauth detected",
            path=path,
        )
        return True

