#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected GLPI directory listing exposed sensitive files and PHP session data, potentially allowing session hij."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GLPI - Directory Listing and Session Exposure Detection',
        'description': 'Detected GLPI directory listing exposed sensitive files and PHP session data, potentially allowing session hijacking or information disclosure.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'glpi', 'misconfig', 'exposure', 'session'],
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
        'references': ['https://glpi-project.org/'],
    }

    def run(self):
        for path in ('/glpi/files/', '/glpi/files/_sessions/', '/files/_sessions/', '/glpi/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('glpi', 'sess_', '_sessions', '_cron', '_dumps',)
            body_all = ('Index of', 'Parent Directory',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="GLPI - Directory Listing and Session Exposure detected",
                    path=path,
                )
                return True
        return False

