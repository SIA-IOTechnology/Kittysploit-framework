#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected HTTP Strict-Transport-Security header with a weak max-age value (less than one year)."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Weak HTTP Strict-Transport-Security - Detect',
        'description': 'Detected HTTP Strict-Transport-Security header with a weak max-age value (less than one year). A low max-age reduces the effectiveness of HSTS, leaving users vulnerable to protocol downgrade attacks and cookie hijacking during the gap period.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'headers', 'hsts'],
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
        'references': [
            'https://owasp.org/www-project-secure-headers/',
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?i)strict-transport-security:\\s*max-age=([0-9]{1,7}|[12][0-9]{7}|30[0-9]{6}|31[0-4][0-9]{5}|315[0-2][0-9]{4}|3153[0-5][0-9]{3})\\b',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='info',
                reason="Weak HTTP Strict-Transport-Security detected",
                path='/',
            )
            return True
        return False

