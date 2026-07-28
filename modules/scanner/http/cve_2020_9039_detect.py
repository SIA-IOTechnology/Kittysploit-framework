#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Couchbase Server versions 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Couchbase Server - Broken Access Control Detection',
        'description': 'Couchbase Server versions 4.0.0, 4.1.0, 4.1.1, 4.5.0, 4.5.1, 4.6.0-4.6.5, 5.0.0, 5.1.1, 5.5.0, and 5.5.1 contain insecure permissions for the projector and indexer REST endpoints caused by unauthenticated access, letting attackers access administrative APIs without authentication, exploit requires no special conditions.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'couchbase', 'unauth'],
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
        'references': ['https://docs.couchbase.com/server/current/index-rest-settings/index.html#Settings'],
        'cve': 'CVE-2020-9039',
    }

    def run(self):
        for path in ('/settings', '/indexer/settings'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('indexer.settings', 'projector.settings', 'max_seckey_size',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='critical',
                    reason="Couchbase Server - Broken Access Control detected",
                    path=path,
                )
                return True
        return False

