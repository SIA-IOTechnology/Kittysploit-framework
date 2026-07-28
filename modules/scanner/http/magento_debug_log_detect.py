#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Magento debug."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Magento Debug Log - Exposure Detection',
        'description': 'Detected Magento debug.log file was publicly accessible. This file contained sensitive debugging information including full server paths, stack traces, customer activity, internal code paths, cache data, and cron job details.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'magento', 'logs', 'misconfig'],
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
        'references': ['https://devdocs.magento.com/guides/v2.4/config-guide/log/log-intro.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/var/log/debug.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('main.DEBUG', 'main.CRITICAL', 'main.ERROR', 'main.INFO', 'Magento\\\\', '/vendor/magento/', 'cache_invalidate', 'Cron Job', 'text/x-log',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Magento Debug Log - Exposure detected",
                path='/var/log/debug.log',
            )
            return True
        return False

