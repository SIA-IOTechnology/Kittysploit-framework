#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exposure of Interswitch Webpay product IDs, MAC keys and access tokens."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Interswitch Webpay - Credentials Exposure Detection',
        'description': 'Exposure of Interswitch Webpay product IDs, MAC keys and access tokens.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'interswitch', 'webpay', 'token'],
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
        'references': ['https://docs.interswitchgroup.com/reference/how-to-use-the-reference'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('interswitch', 'webpay', 'mackey',)
        body_regexes = ('macKey["\']?\\s*[:=]\\s*["\']?[0-9A-Fa-f]{64}["\']?', 'payItemId["\']?\\s*[:=]\\s*["\']?\\d+["\']?',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, re.I) for rx in body_regexes)):
            self.set_info(
                severity='info',
                reason="Interswitch Webpay - Credentials Exposure detected",
                path='/',
            )
            return True
        return False

