#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in Tekon allows remote unauthenticated users to disclose the Log of the remote device."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tekon - Unauthenticated Log Leak Detection',
        'description': 'A vulnerability in Tekon allows remote unauthenticated users to disclose the Log of the remote device',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'tekon', 'exposure', 'unauth', 'vuln'],
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
            'https://medium.com/@bertinjoseb/post-auth-rce-based-in-malicious-lua-plugin-script-upload-scada-controllers-located-in-russia-57044425ac38',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/log.cgi', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('-- Logs begin at', 'end at',)
        header_any = ('text/plain',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='low',
                reason="Tekon - Unauthenticated Log Leak detected",
                path='/cgi-bin/log.cgi',
            )
            return True
        return False

