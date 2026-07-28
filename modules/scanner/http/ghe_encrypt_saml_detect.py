#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This template checks if Encrypted SAML (Security Assertion Markup Language) is enabled on a GitHub Enterprise ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GitHub Enterprise - Encrypted SAML Detection',
        'description': 'This template checks if Encrypted SAML (Security Assertion Markup Language) is enabled on a GitHub Enterprise instance.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'github', 'ghe', 'saml'],
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
            'https://docs.github.com/en/enterprise-server@3.10/admin/managing-iam/using-saml-for-enterprise-iam/enabling-encrypted-assertions',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/saml/metadata', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            'EntityDescriptor',
            'KeyDescriptor',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="GitHub Enterprise - Encrypted SAML detected",
                path='/saml/metadata',
            )
            return True
        return False

