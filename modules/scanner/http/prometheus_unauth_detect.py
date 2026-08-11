#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects unauthenticated access to Prometheus Time Series Collection and Processing Server by checking for spec."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.probe_guard import looks_like_prometheus_config_api, validate_json_probe
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Prometheus Monitoring System - Unauthenticated Detection',
        'description': 'Detects unauthenticated access to Prometheus Time Series Collection and Processing Server by checking for specific elements in the response from the `/graph` endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'unauth', 'prometheus', 'misconfig', 'vuln'],
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
        for path in ('/api/v1/status/config',):
            data, _response = validate_json_probe(
                self.http_request,
                path,
                looks_like_prometheus_config_api,
            )
            if data:
                self.set_info(
                    severity='high',
                    reason="Prometheus Monitoring System - Unauthenticated detected",
                    path=path,
                )
                return True

        r = self.http_request(method="GET", path='/config', allow_redirects=False)
        if not r or r.status_code != 200 or is_html_response(r):
            return False
        body = r.text or ""
        if all(token in body for token in ('global:', 'scrape_configs:', 'scrape_interval')):
            self.set_info(
                severity='high',
                reason="Prometheus Monitoring System - Unauthenticated detected",
                path='/config',
            )
            return True
        return False

