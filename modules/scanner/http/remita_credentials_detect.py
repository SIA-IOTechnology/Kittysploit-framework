#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed Remita merchant IDs, API keys, and secret hashes in application source code, configuration fi."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Remita Merchant ID & API Key - Exposure Detection',
        'description': 'Detected exposed Remita merchant IDs, API keys, and secret hashes in application source code, configuration files, or publicly accessible assets.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'remita', 'fintech', 'tinlance', 'lloydcoder', 'token'],
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
        'references': ['https://api.remita.net/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('remita', 'merchantid', 'publickey',)
        body_regexes = ('merchantId["\']?\\s*[:=]\\s*["\']?\\d{10,}["\']?',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, re.I) for rx in body_regexes)):
            self.set_info(
                severity='low',
                reason="Remita Merchant ID & API Key - Exposure detected",
                path='/',
            )
            return True
        return False

