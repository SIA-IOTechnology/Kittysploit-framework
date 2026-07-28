#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects a Apache Polaris server, the interoperable, open source catalog for Apache Iceberg."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Polaris - Information Disclosure Detection',
        'description': 'Detects a Apache Polaris server, the interoperable, open source catalog for Apache Iceberg.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'apache', 'polaris', 'metrics', 'misconfig'],
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
        'references': ['https://github.com/apache/polaris'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/q/metrics', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('application="Polaris"', 'org.apache.polaris',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Apache Polaris - Information Disclosure detected",
                path='/q/metrics',
            )
            return True
        return False

