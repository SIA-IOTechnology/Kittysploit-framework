#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Boot Metrics Actuator endpoint was detected, which may expose system metrics information."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Springboot Actuator Metrics - Exposure Detection',
        'description': 'Spring Boot Metrics Actuator endpoint was detected, which may expose system metrics information. This template detects both older Spring Boot 1.x format and newer 2.x/3.x format.',
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
    }

    def run(self):
        for path in ('/metrics', '/actuator/metrics'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            body_any = ('application/json', 'application/vnd.spring-boot', '{"mem":', '{"heap":', '{"nonheap":', '{"threads":', '{"gc":', '{"names":[', '"jvm.memory', '"process.cpu',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='low',
                    reason="Springboot Actuator Metrics - Exposure detected",
                    path=path,
                )
                return True
        return False

