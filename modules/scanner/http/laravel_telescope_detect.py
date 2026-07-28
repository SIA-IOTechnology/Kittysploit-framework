#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Telescope provides insight into the requests coming into your application, exceptions, log entries, database q."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Laravel Telescope Disclosure Detection',
        'description': 'Telescope provides insight into the requests coming into your application, exceptions, log entries, database queries, queued jobs, mail, notifications, cache operations, scheduled tasks, variable dumps, and more.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'laravel', 'disclosure', 'logs', 'vuln'],
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
        'references': ['https://laravel.com/docs/8.x/telescope'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/telescope/requests', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<title>Telescope</title>', 'Requests', 'Commands', 'Schedule',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Laravel Telescope Disclosure detected",
                path='/telescope/requests',
            )
            return True
        return False

