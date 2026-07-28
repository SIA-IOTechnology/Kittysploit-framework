#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Dynatrace Real User Monitoring (RUM) and OneAgent artifacts."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dynatrace RUM - Tech Detect',
        'description': 'Detects Dynatrace Real User Monitoring (RUM) and OneAgent artifacts.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'rum', 'dynatrace'],
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
        'references': ['https://docs.dynatrace.com/docs/observe/digital-experience/rum-concepts/rum-overview'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = ('ruxitagentjs_', 'data-dtconfig=',)
        if any(m in body for m in body_markers):
            self.set_info(
                severity='info',
                reason="Dynatrace RUM - Tech detected",
                path='/',
            )
            return True
        return False

