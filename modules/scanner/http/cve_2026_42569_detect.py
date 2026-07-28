#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpVMS < 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpVMS < 7.0.6 - Legacy Importer Authorization Bypass Detection',
        'description': 'phpVMS < 7.0.6 contains an authentication bypass caused by unauthenticated access to a legacy import feature, letting unauthenticated attackers access restricted functionality, exploit requires no special privileges.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'phpvms', 'auth-bypass', 'unauth'],
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
            'https://github.com/phpvms/phpvms/security/advisories/GHSA-fv26-4939-62fh',
            'https://github.com/phpvms/phpvms/commit/f59ba8e0e8fc25c60c3faf14e526cfd49df3f7dc',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-42569',
        ],
        'cve': 'CVE-2026-42569',
    }

    def run(self):
        r = self.http_request(method="GET", path='/importer', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('import configuration', 'database config', 'start importer', 'wipe out your existing data', 'importer/config',)
        body_all = ('importer', 'phpvms',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="phpVMS < 7.0.6 - Legacy Importer Authorization Bypass detected",
                path='/importer',
            )
            return True
        return False

