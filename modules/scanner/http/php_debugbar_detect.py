#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The DebugBar integrates easily into projects and can display profiling data from any part of your application."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Php Debug Bar - Exposure Detection',
        'description': 'The DebugBar integrates easily into projects and can display profiling data from any part of your application.This template detects exposed PHP Debug Bars by looking for known response bodies and the `phpdebugbar-id` in headers.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'php', 'phpdebug', 'exposure', 'debug', 'vuln'],
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
            'https://hackerone.com/reports/1883806',
            'http://phpdebugbar.com/',
            'https://github.com/maximebf/php-debugbar',
        ],
    }

    def run(self):
        for path in ('/', '/_debugbar/open'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('application/json',)
            body_all = ('phpdebugbar', 'widget', '{\\', ') && contains(content_type,')
            header_any = ('phpdebugbar-id',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Php Debug Bar - Exposure detected",
                    path=path,
                )
                return True
        return False

