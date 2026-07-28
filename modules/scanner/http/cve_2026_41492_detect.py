#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dgraph <= 25."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dgraph <= 25.3.2 - Admin Token Disclosure Detection',
        'description': 'Dgraph <= 25.3.2 contains an information disclosure caused by unauthenticated access to the /debug/vars endpoint , which publishes the cmdline variable including the --security token= flag, letting unauthenticated remote attackers retrieve the admin token and access admin-only endpoints, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'dgraph', 'exposure', 'token'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/dgraph-io/dgraph/security/advisories/GHSA-vvf7-6rmr-m29q',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-41492',
        ],
        'cve': 'CVE-2026-41492',
    }

    def run(self):
        path = '/debug/vars'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('cmdline', 'token=',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='critical',
                reason='Dgraph <= 25.3.2 - Admin Token Disclosure detected',
                path=path,
            )
            return True
        return False

