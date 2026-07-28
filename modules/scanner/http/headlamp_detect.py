#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Headlamp Kubernetes Web UI panel exposed, which could lead to unauthorized access to Kubernetes clust."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Headlamp Kubernetes UI Panel - Detect',
        'description': 'Detected Headlamp Kubernetes Web UI panel exposed, which could lead to unauthorized access to Kubernetes cluster management if not properly secured.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'panel', 'headlamp', 'kubernetes', 'exposure'],
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
        'references': ['https://headlamp.dev/', 'https://github.com/kubernetes-sigs/headlamp'],
    }

    def run(self):
        for path in ('/settings/plugins', '/settings/cluster'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Headlamp: Kubernetes Web UI', 'headlampBaseUrl',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Headlamp Kubernetes UI Panel detected",
                    path=path,
                )
                return True
        return False

