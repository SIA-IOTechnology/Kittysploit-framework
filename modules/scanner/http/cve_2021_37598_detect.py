#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WP Cerber < 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP Cerber < 8.9.3 - Broken Access Control Detection',
        'description': "WP Cerber < 8.9.3 contains a bypass of /wp-json access control caused by improper handling of trailing '?' character, letting unauthorized users access protected REST API endpoints, exploit requires sending a request with a trailing '?'.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'wp-cerber', 'access-control', 'rest-api', 'exposure', 'auth-bypass'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/mandiant/Vulnerability-Disclosures/blob/master/FEYE-2021-0024/FEYE-2021-0024.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-37598',
        ],
        'cve': 'CVE-2021-37598',
    }

    def run(self):
        path = '/wp-json'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/wp-json?'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"name":', '"url":', '"home":', '"description":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='WP Cerber < 8.9.3 - Broken Access Control detected', path=path)
            return True
        return False

