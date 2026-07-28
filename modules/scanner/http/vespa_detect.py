#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vespa, an open-source big-data serving engine used for low-latency search, recommendation, and vector/embeddin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vespa - Detect',
        'description': 'Vespa, an open-source big-data serving engine used for low-latency search, recommendation, and vector/embedding retrieval, increasingly deployed as the retrieval backend in AI and RAG (retrieval-augmented generation) pipelines, was detected. Exposed config-server or container endpoints could have leaked application deployment metadata, cluster status, and version information, and may have allowed unauthenticated access to indexed/vectorized data if the query API was left open.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'vespa', 'ai', 'vector-db', 'search'],
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
            'https://vespa.ai/',
            'https://github.com/vespa-engine/vespa',
            'https://docs.vespa.ai/en/reference/state-v1.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/ApplicationStatus', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = ('"vespa"', '"version"',)
        if any(m in body for m in body_markers):
            self.set_info(
                severity='info',
                reason="Vespa detected",
                path='/ApplicationStatus',
            )
            return True
        return False

