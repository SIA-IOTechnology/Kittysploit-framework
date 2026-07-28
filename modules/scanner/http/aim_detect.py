#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aim, an open-source, self-hosted AI/ML experiment tracking tool used to log, query, and visualize machine lear."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Aim Panel - Detect',
        'description': 'Aim, an open-source, self-hosted AI/ML experiment tracking tool used to log, query, and visualize machine learning training runs, was detected by matching its distinctive web UI page title and meta description, thereby minimizing false positives associated with the generic term "Aim".',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'aim', 'ml', 'ai', 'mlops'],
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
        'references': ['https://github.com/aimhubio/aim', 'https://aimstack.io'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            '<title>Aim</title>',
            'Open-source, self-hosted AI experiment tracking tool',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="Aim Panel detected",
                path='/',
            )
            return True
        return False

