#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft Exchange Web Services was detected."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft Exchange Web Service - Detect',
        'description': 'Microsoft Exchange Web Services was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'ms', 'microsoft', 'exchange', 'tech'],
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
            'https://learn.microsoft.com/en-us/exchange/client-developer/exchange-web-services/start-using-web-services-in-exchange',
            'https://pentestlab.blog/tag/ews/',
        ],
    }

    def run(self):
        for path in ('/EWS/Exchange.asmx', '/owa/service.svc'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_regexes = ('(?i)(X-Owa-Version:)',)
            if any(re.search(rx, headers, 0) for rx in header_regexes):
                self.set_info(
                    severity='info',
                    reason="Microsoft Exchange Web Service detected",
                    path=path,
                )
                return True
        return False

