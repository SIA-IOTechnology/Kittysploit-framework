#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed Wekan sign-up functionality, indicating that unauthenticated users could access the registrat."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wekan Sign Up Page - Exposure Detection',
        'description': 'Detected exposed Wekan sign-up functionality, indicating that unauthenticated users could access the registration page and potentially create new accounts.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'wekan', 'sign-up', 'register', 'exposure'],
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
        'references': ['https://wekan.fi/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/sign-up', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('__meteor_runtime_config__', 'Wekan',)
        body_regexes = ('<link rel="stylesheet".*meteor_css_resource=true',)
        if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Wekan Sign Up Page - Exposure detected",
                path='/sign-up',
            )
            return True
        return False

