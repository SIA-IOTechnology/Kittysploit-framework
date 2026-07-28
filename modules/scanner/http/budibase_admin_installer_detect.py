#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Budibase admin setup checklist endpoint was publicly accessible with no admin user created, allowing ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Budibase - Admin Installer Detection',
        'description': 'Detected Budibase admin setup checklist endpoint was publicly accessible with no admin user created, allowing unauthenticated users to complete setup and gain full platform control.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'exposure', 'setup', 'installer', 'budibase'],
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
        'references': ['https://github.com/Budibase/budibase'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/global/configs/checklist', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('application/json',)
        body_all = (':{\\', ':false', '/builder/portal')
        header_any = ('X-Budibase-Tenant-Id',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Budibase - Admin Installer detected",
                path='/api/global/configs/checklist',
            )
            return True
        return False

