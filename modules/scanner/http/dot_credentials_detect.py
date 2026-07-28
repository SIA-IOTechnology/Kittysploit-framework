#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected the presence of a ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dot Credentials - Exposure Detection',
        'description': 'Detected the presence of a .credentials file and extracts sensitive authentication tokens, passwords, or API keys.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'config', 'credentials', 'sensitive', 'token'],
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
        r = self.http_request(method="GET", path='/.credentials', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        if self.is_same_as_index(r, path='/.credentials'):
            return False
        body = r.text or ""
        low = body.lower()
        if '<html' in low or '<!doctype' in low or '<script' in low:
            return False
        body_any = (
            'client_id', 'client_secret', 'access_token', 'refresh_token',
            'password', 'aws_access_key_id',
        )
        if any(m in low for m in body_any):
            self.set_info(
                severity='high',
                reason="Dot Credentials - Exposure detected",
                path='/.credentials',
            )
            return True
        return False

