#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Searches for exposed webcams by querying the /mobile."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XP Webcam Viewer Page Detection',
        'description': 'Searches for exposed webcams by querying the /mobile.html endpoint and the existence of webcamXP in the body.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'iot', 'webcam'],
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
        r = self.http_request(method="GET", path='/mobile.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_any = ('webcams and ip cameras server for windows', 'Please provide a valid username/password to access this server.',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="XP Webcam Viewer Page detected",
                path='/mobile.html',
            )
            return True
        return False

