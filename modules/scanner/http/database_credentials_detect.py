#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Internal file exposed containing database credentials."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Database Credentials File Exposure Detection',
        'description': 'Internal file exposed containing database credentials.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'database', 'config', 'files', 'vuln'],
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
        'references': ['https://github.com/maurosoria/dirsearch/blob/master/db/dicc.txt'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/database_credentials.inc', allow_redirects=False)
        if not r or r.status_code not in (200, 401, 403):
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('DATABASE_USER', 'DB_USER', 'USERNAME', 'USER', 'DATABASE_PASS', 'DB_PASS', 'PASSWORD', 'PASS', 'Access denied', 'Unauthorized',)
        header_any = ('Content-Type: text/plain', 'Content-Type: application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='low',
                reason="Database Credentials File Exposure detected",
                path='/database_credentials.inc',
            )
            return True
        return False

