#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Determined AI, an open-source deep learning training platform that provides distributed training, hyperparamet."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Determined AI Panel - Detect',
        'description': 'Determined AI, an open-source deep learning training platform that provides distributed training, hyperparameter tuning, and experiment tracking through a web-based UI and a REST/gRPC-gateway API served by the "master" component, was detected by matching the application title and meta description served at the application root.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'determined-ai', 'ml', 'ai', 'mlops'],
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
                'confidence_min': {
                },
                'confidence_min_any': {
                },
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
                'option_bindings': {
                },
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://github.com/determined-ai/determined', 'https://docs.determined.ai'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            'Determined Deep Learning Training Platform',
            '<title>Determined</title>',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="Determined AI Panel detected",
                path='/',
            )
            return True
        return False

