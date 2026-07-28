#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects ZenML Dashboard Panel - Detect."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZenML Dashboard Panel - Detect',
        'description': 'Detects ZenML Dashboard Panel - Detect.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'zenml', 'login'],
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
    }

    def run(self):
        r = self.http_request(method="GET", path='/login?route=%2Fworkspaces%2Fdefault%3F', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            'ZenML - Dashboard',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="ZenML Dashboard Panel detected",
                path='/login?route=%2Fworkspaces%2Fdefault%3F',
            )
            return True
        return False

