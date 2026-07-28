#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Test CGI script was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Test CGI Script - Detect',
        'description': 'Test CGI script was detected. Response page returned by this CGI script exposes a list of server environment variables.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'cgi', 'vuln'],
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
            'https://www.acunetix.com/vulnerabilities/web/test-cgi-script-leaking-environment-variables/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/printenv.pl', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('MYSQL_HOME', 'OPENSSL_CONF', 'REMOTE_ADDR', 'SERVER_ADMIN', 'Environment Variables:',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Test CGI Script detected",
                path='/cgi-bin/printenv.pl',
            )
            return True
        return False

