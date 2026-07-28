#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Uptime Kuma setup page is publicly accessible with needSetup enabled, allowing unauthenticated users ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Uptime Kuma - Installer Detection',
        'description': 'Detected Uptime Kuma setup page is publicly accessible with needSetup enabled, allowing unauthenticated users to complete installation and gain full admin access by access /setup-database.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'exposure', 'setup', 'installer', 'uptime-kuma'],
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
        'references': ['https://github.com/louislam/uptime-kuma'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/setup-database-info', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/json',)
        body_all = (':true', 'runningSetup', 'isEnabledEmbeddedMariaDB')
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Uptime Kuma - Installer detected",
                path='/setup-database-info',
            )
            return True
        return False

