#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""H2O Driverless AI, a commercial automated machine learning (AutoML) platform that provides a web UI typically ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'H2O Driverless AI Panel - Detect',
        'description': 'H2O Driverless AI, a commercial automated machine learning (AutoML) platform that provides a web UI typically served on port 12345 for building and deploying machine learning models, was detected. An exposed H2O Driverless AI login panel was identified. It is distinct from H2O Wave and H2O-3/Flow, which are separate H2O.ai products with different branding, ports, and UIs.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'h2o-driverless-ai', 'ml', 'ai', 'automl'],
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
            'https://h2o.ai/platform/ai-cloud/make/driverless-ai/',
            'https://docs.h2o.ai/driverless-ai/latest-stable/docs/userguide/index.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/login', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_markers = (
            'driverless ai',
        )
        body_hit = any(m in body for m in body_markers)
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        header_markers = (
            'server: h2o driverless ai',
        )
        if body_hit and any(m in headers for m in header_markers):
            self.set_info(
                severity='info',
                reason="H2O Driverless AI Panel detected",
                path='/login',
            )
            return True
        return False

