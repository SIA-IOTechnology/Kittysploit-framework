#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vanna AI is a chat interface for text-to-SQL generation using natural language."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vanna AI Panel - Detect',
        'description': 'Vanna AI is a chat interface for text-to-SQL generation using natural language. This template detects the presence of a Vanna AI chat panel.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'vanna', 'ai', 'sql', 'chat'],
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
        'references': ['https://github.com/vanna-ai/vanna', 'https://vanna.ai'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = ('vanna-',)
        body_regexes = ('(?i)<title>[^<]*Vanna[^<]*</title>',)
        if any(m in body for m in body_markers) and any(re.search(rx, body, 0) for rx in body_regexes):
            self.set_info(
                severity='info',
                reason="Vanna AI Panel detected",
                path='/',
            )
            return True
        return False

