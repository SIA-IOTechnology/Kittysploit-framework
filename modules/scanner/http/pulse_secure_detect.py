#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pulse Secure VPN login panel was detected."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pulse Secure VPN Login Panel - Detect',
        'description': 'Pulse Secure VPN login panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'pulse', 'vpn'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
        for path in ('/dana-na/auth/url_default/welcome.cgi', '/dana-na/auth/url_2/welcome.cgi', '/dana-na/auth/url_3/welcome.cgi'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('(?i)/dana-na/css/ds(_[a-f0-9]{64})?.css',)
            body_re_hit = any(re.search(rx, body, 0) for rx in body_regexes)
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_markers = ('/dana-na/auth/welcome.cgi',)
            if body_re_hit:
                self.set_info(
                    severity='info',
                    reason="Pulse Secure VPN Login Panel detected",
                    path=path,
                )
                return True
        return False

