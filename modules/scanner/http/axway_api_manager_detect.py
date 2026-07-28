#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Axway API Manager panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Axway API Manager Panel - Detect',
        'description': 'Axway API Manager panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'axway', 'login'],
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
        'references': [
            'https://docs.axway.com/bundle/axway-open-docs/page/docs/index.html',
            'https://www.postman.com/api-evangelist/axway/api/06c40de2-3954-4c68-ae10-a7eded330b05',
            'https://www.postman.com/api-evangelist/axway/api/ce2ac156-4353-46b9-b148-944ab7721ed6',
        ],
    }

    def run(self):
        for path in ('/api/portal/v1.4/appinfo', '/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            body_markers = (
                'axway api manager login',
                'vordel/apiportal/app-login',
            )
            if any(m in body for m in body_markers):
                self.set_info(
                    severity='info',
                    reason="Axway API Manager Panel detected",
                    path=path,
                )
                return True
        return False

