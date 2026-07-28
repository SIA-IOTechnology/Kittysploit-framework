#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Apache Spark Web UI exposed environment variables and application information without authentication,."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Spark Environment - Exposure Detection',
        'description': 'Detected Apache Spark Web UI exposed environment variables and application information without authentication, potentially revealing sensitive configuration details.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'apache', 'spark', 'missconfig', 'environment', 'bigdata'],
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
        'references': ['https://spark.apache.org/docs/latest/monitoring.html'],
    }

    def run(self):
        for path in ('/api/v1/applications', '/environment/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('sparkProperties', 'appSparkVersion', 'Runtime Information', 'Spark Properties', 'spark.app.name', 'sparkUser',)
            body_all = ('Spark', 'Java',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Apache Spark Environment - Exposure detected",
                    path=path,
                )
                return True
        return False

