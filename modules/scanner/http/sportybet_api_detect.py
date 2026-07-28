#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed internal tokens and administrative endpoints belonging to online betting platforms."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SportyBet / BetKing Admin or API Token - Exposure Detection',
        'description': 'Detected exposed internal tokens and administrative endpoints belonging to online betting platforms.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'betting', 'sportybet', 'betking', 'token'],
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
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('sportybet', 'betking', 'bet9ja',)
        body_regexes = ('Bearer\\s+[A-Za-z0-9_-]{50,}\\.[A-Za-z0-9_-]{50,}\\.[A-Za-z0-9_-]{50,}', 'token["\']?\\s*[:=]\\s*["\']?eyJ[A-Za-z0-9_-]{100,}["\']?',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, re.I) for rx in body_regexes)):
            self.set_info(
                severity='info',
                reason="SportyBet / BetKing Admin or API Token - Exposure detected",
                path='/',
            )
            return True
        return False

