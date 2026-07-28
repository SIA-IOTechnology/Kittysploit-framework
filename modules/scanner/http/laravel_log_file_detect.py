#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The log file of this Laravel web app might reveal details on the inner workings of the app, possibly even toke."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Laravel log file publicly accessible Detection',
        'description': 'The log file of this Laravel web app might reveal details on the inner workings of the app, possibly even tokens, credentials or personal information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'laravel', 'logs', 'vuln'],
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
        'references': ['https://laravel.com/docs/master/logging'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/storage/logs/laravel.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('InvalidArgumentException', 'local.ERROR', 'ErrorException', 'syntax error',)
        header_any = ('text/plain', 'text/x-log',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Laravel log file publicly accessible detected",
                path='/storage/logs/laravel.log',
            )
            return True
        return False

