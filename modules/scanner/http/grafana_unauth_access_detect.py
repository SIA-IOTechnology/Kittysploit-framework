#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Grafana instances configured with anonymous access enabled, allowing unauthenticated users to access d."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Grafana Unauthenticated Access Detection',
        'description': 'Detects Grafana instances configured with anonymous access enabled, allowing unauthenticated users to access dashboards, data sources, organization info, and potentially sensitive monitoring data without any credentials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'grafana', 'misconfig', 'unauth', 'exposure', 'dashboard'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
        for path in ('/api/search?type=dash-db', '/api/dashboards/home', '/dashboard', '/api/org', '/api/users', '/api/datasources', '/api/frontend/settings'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('application/json', ':\\')
            body_all = ('dashboards:read', 'name\\', 'Dashboard list')
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Grafana Unauthenticated Access detected",
                    path=path,
                )
                return True
        return False

