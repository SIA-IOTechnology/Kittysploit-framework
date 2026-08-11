#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Prometheus config API endpoint was discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.probe_guard import looks_like_prometheus_config_api, validate_json_probe


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Prometheus Config API Endpoint Discovery Detection',
        'description': 'A Prometheus config API endpoint was discovered. The config endpoint returns the loaded Prometheus configuration file along with the addresses of targets and alerting/discovery services alongside the credentials required to access them. Usually, Prometheus replaces the passwords in the credentials config configuration field with the placeholder <secret> (although this still leaks the username).',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'prometheus', 'config', 'misconfig', 'vuln'],
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
        'references': ['https://jfrog.com/blog/dont-let-prometheus-steal-your-fire/'],
    }

    def run(self):
        path = '/api/v1/status/config'
        data, _response = validate_json_probe(
            self.http_request,
            path,
            looks_like_prometheus_config_api,
        )
        if data:
            self.set_info(
                severity='info',
                reason="Prometheus Config API Endpoint Discovery detected",
                path=path,
            )
            return True
        return False

