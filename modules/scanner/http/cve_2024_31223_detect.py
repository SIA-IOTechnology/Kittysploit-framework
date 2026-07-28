#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fides versions 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fides Privacy Center ≤ 2.39.1 - Server-Side URL Disclosure Detection',
        'description': 'Fides versions 2.19.0 to before 2.39.2rc0 contain an information disclosure caused by unauthenticated HTTP GET request to the Privacy Center, letting attackers access the SERVER_SIDE_FIDES_API_URL, which may reveal server configuration details, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'vuln', 'ethyca', 'fides', 'disclosure', 'vkev'],
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
            'https://github.com/ethyca/fides/commit/0555080541f18a5aacff452c590ac9a1b56d7097',
            'https://github.com/ethyca/fides/security/advisories/GHSA-53q7-4874-24qg',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-31223',
        ],
        'cve': 'CVE-2024-31223',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('SERVER_SIDE_FIDES_API_URL',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Fides Privacy Center ≤ 2.39.1 - Server-Side URL Disclosure detected",
                path='/',
            )
            return True
        return False

