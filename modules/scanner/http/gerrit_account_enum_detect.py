#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gerrit Code Review exposes the /accounts/ REST API endpoint which can be used to enumerate user accounts."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gerrit Code Review - Account Enumeration Detection',
        'description': 'Gerrit Code Review exposes the /accounts/ REST API endpoint which can be used to enumerate user accounts.The endpoint allows querying for accounts by username, email, or name, potentially revealing sensitive user information including account IDs, names, emails, and usernames without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'gerrit', 'enum', 'exposure', 'misconfig'],
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
        'references': [
            'https://gerrit-review.googlesource.com/Documentation/rest-api-accounts.html',
            'https://gerrit-documentation.storage.googleapis.com/Documentation/2.11/rest-api-accounts.html',
        ],
    }

    def run(self):
        for path in ('/accounts/?q=a&n=10', '/accounts/?suggest&q=a&n=10'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('_account_id', 'username',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Gerrit Code Review - Account Enumeration detected",
                    path=path,
                )
                return True
        return False

