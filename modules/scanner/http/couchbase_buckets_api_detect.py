#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Couchbase Buckets REST API without authentication was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Couchbase Buckets Unauthenticated REST API - Detect',
        'description': 'Couchbase Buckets REST API without authentication was detected.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'couchbase'],
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
            'https://docs.couchbase.com/server/current/rest-api/rest-bucket-intro.html',
            'https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-couchbase-bucket.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/pools/default/buckets', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"couchbase":', '"bucket":', '"data":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Couchbase Buckets Unauthenticated REST API detected",
                path='/pools/default/buckets',
            )
            return True
        return False

