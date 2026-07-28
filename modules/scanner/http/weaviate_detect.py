#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected an exposed Weaviate instance by accessing its API endpoints."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Weaviate - Exposure Detection',
        'description': 'Detected an exposed Weaviate instance by accessing its API endpoints. Verified exposure by identifying meta information, schema details, and specific endpoint references in the response, confirming that the instance was publicly accessible.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'weaviate', 'exposure', 'api', 'vuln'],
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
    }

    def run(self):
        r = self.http_request(method="GET", path='/v1/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Meta information about this instance/cluster', 'view complete schema',)
        body_regexes = ('"href":"/v1/schema"',)
        if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='low',
                reason="Weaviate - Exposure detected",
                path='/v1/',
            )
            return True
        return False

