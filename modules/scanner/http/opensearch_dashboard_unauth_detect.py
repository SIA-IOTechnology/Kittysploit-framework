#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenSearch Dashboard is a visualization and management tool for OpenSearch."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenSearch Dashboard - Unauth Access Detection',
        'description': 'OpenSearch Dashboard is a visualization and management tool for OpenSearch. This template detects instances that are accessible without authentication, potentially exposing sensitive data and system information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'opensearch', 'dashboard', 'misconfig', 'unauth', 'vuln'],
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
        'references': ['https://opensearch.org/docs/latest/dashboards/index/'],
    }

    def run(self):
        path = '/app/home#/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('/ui/fonts/source_sans_3/SourceSans3', "font-family: 'Source Code Pro", 'OpenSearch',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='OpenSearch Dashboard - Unauth Access detected', path=path)
            return True
        return False

