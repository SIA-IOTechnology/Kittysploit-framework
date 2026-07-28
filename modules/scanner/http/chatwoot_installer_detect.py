#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected chatwoot instance with the initial installation onboarding page accessible at /installation/onboardin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chatwoot - Installation Detection',
        'description': 'Detected chatwoot instance with the initial installation onboarding page accessible at /installation/onboarding, enabling unauthenticated users to create the first Super Admin account and gain full platform control.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'install', 'exposure', 'chatwoot', 'unauth'],
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
        'references': [
            'https://github.com/chatwoot/chatwoot',
            'https://www.chatwoot.com/docs/self-hosted/monitoring/super-admin-sidekiq',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/installation/onboarding', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('SuperAdmin | Chatwoot', 'Howdy, Welcome to Chatwoot', 'Finish Setup',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Chatwoot - Installation detected",
                path='/installation/onboarding',
            )
            return True
        return False

