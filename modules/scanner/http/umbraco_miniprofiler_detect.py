#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected the exposure of the MiniProfiler debugging interface in Umbraco CMS."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Umbraco Mini Profiler - Exposure Detection',
        'description': 'Detected the exposure of the MiniProfiler debugging interface in Umbraco CMS. When exposed, it can reveal sensitive information including SQL queries, execution times, stack traces, and internal application details.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'umbraco', 'miniprofiler', 'exposure', 'debug', 'misconfig'],
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
        'references': ['https://miniprofiler.com/', 'https://umbraco.com/'],
    }

    def run(self):
        for path in ('/mini-profiler-resources/results', '/umbraco/mini-profiler-resources/results'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('StartupProfiler', 'var profiler =', '"DurationMilliseconds"',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="Umbraco Mini Profiler - Exposure detected",
                    path=path,
                )
                return True
        return False

