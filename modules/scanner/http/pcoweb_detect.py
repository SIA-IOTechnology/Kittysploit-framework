#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects pCOWeb Panel - Detect."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'pCOWeb Panel - Detect',
        'description': 'Detects pCOWeb Panel - Detect.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'pcoweb', 'login'],
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
            'https://docs.librenms.org/Support/Device-Notes/Carel-pCOweb-Devices/#:~:text=Accessing%20the%20pCOWeb%20card,-Log%20on%20to&text=The%20default%20username%20and%20password%20is%20admin%2Ffadmin%20.',
        ],
    }

    def run(self):
        for path in ('/', '/http/index.html'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('<title>(.*)pCOWeb(.*)</title>', 'pCOWeb</h2>',)
            if any(re.search(rx, body, 0) for rx in body_regexes):
                self.set_info(
                    severity='info',
                    reason="pCOWeb Panel detected",
                    path=path,
                )
                return True
        return False

