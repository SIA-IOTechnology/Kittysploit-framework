#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Appspace is the workplace experience platform for your whole team that lets you manage it all – from employee ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Appspace Login Panel - Detect',
        'description': 'Appspace is the workplace experience platform for your whole team that lets you manage it all – from employee communications to your physical office spaces.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'appspace'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
                'confidence_min': {
                },
                'confidence_min_any': {
                },
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
                'option_bindings': {
                },
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://www.appspace.com/'],
    }

    def run(self):
        markers = (
            '.appspace-ui',
            'appspace-logo',
            '<title>appspace</title>',
            'class="btnssoappspace',
            'sign in to appspace core',
        )
        for path in ('/', '/app/login.aspx', '/signin/#!/login?returnUrl=%2Fapp%2Fdefault.aspx'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            if any(m in body for m in markers):
                self.set_info(
                    severity='info',
                    reason="Appspace Login Panel detected",
                    path=path,
                )
                return True
        return False

