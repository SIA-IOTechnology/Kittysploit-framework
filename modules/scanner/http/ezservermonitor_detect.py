#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed eZ Server Monitor instances that revealed sensitive server information, including hostname, O."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'eZ Server Monitor - Exposure Detection',
        'description': 'Detected exposed eZ Server Monitor instances that revealed sensitive server information, including hostname, OS, kernel version, CPU details, memory usage, disk space, network interfaces with IP addresses, service status, and user login history.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'exposure', 'ezservermonitor', 'monitoring'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://github.com/shevabam/ezservermonitor-web',
            'https://www.ezservermonitor.com/esm-web/features',
        ],
    }

    def run(self):
        for path in ('/', '/esm/', '/monitoring/', '/ezservermonitor/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('web/css/frontend.css', '<span class="icon-gauge"></span>eSM',)
            body_all = ('<title>eZ Server Monitor', 'eZ Server Monitor - v',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="eZ Server Monitor - Exposure detected",
                    path=path,
                )
                return True
        return False

