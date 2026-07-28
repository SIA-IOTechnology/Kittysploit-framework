#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected AdminBro/AdminJS admin panel was exposed without authentication, allowing unauthenticated users to ac."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AdminBro Dashboard - Unauthenticated Access Detection',
        'description': 'Detected AdminBro/AdminJS admin panel was exposed without authentication, allowing unauthenticated users to access the admin dashboard and potentially view, modify, or delete sensitive data. This misconfiguration occurred when developers used buildRouter() instead of buildAuthenticatedRouter().',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'adminbro', 'adminjs', 'misconfig', 'exposure', 'unauth', 'panel'],
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
        'references': ['https://docs.adminjs.co/basics/authentication', 'https://github.com/SoftwareBrothers/adminjs'],
    }

    def run(self):
        for path in ('/admin', '/admin/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('text/html',)
            body_all = ('window.REDUX_STATE', 'window.AdminBro', ':null', ':[')
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="AdminBro Dashboard - Unauthenticated Access detected",
                    path=path,
                )
                return True
        return False

