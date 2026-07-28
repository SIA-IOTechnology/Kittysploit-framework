#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASP."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ASP.NET Trace.AXD - Exposure Detection',
        'description': 'ASP.NET Trace.AXD information was exposed.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'logs', 'asp'],
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
        'references': ['https://www.rapid7.com/db/vulnerabilities/spider-asp-dot-net-trace-axd/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/Trace.axd', allow_redirects=False)
        if not r or r.status_code not in (200, 403):
            return False
        body = r.text or ""
        body_any = ('<td><h1>Application Trace</h1></td>', '<title>Trace Error</title>', 'The current trace settings prevent trace.axd from being viewed',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='low',
                reason="ASP.NET Trace.AXD - Exposure detected",
                path='/Trace.axd',
            )
            return True
        return False

