#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Ambassador API Gateway diagnostics portal, revealing service mappings, API endpoints, routing configu."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ambassador API Gateway Diagnostics - Exposure Detection',
        'description': 'Detected Ambassador API Gateway diagnostics portal, revealing service mappings, API endpoints, routing configurations, and internal cluster information.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'ambassador', 'api', 'gateway', 'misconfig'],
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
        'references': [
            'https://www.getambassador.io/docs/edge-stack/latest/',
            'https://www.getambassador.io/docs/edge-stack/latest/topics/running/diagnostics/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/ambassador/v0/diag/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Cluster ID', 'Ambassador Route Table', 'Ambassador namespace',)
        body_all = ('Ambassador Diagnostic Overview', 'Ambassador version',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Ambassador API Gateway Diagnostics - Exposure detected",
                path='/ambassador/v0/diag/',
            )
            return True
        return False

