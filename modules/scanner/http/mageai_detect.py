#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mage AI (mage."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mage AI Panel - Detect',
        'description': 'Mage AI (mage.ai / github.com/mage-ai/mage-ai) is an open-source data pipeline + orchestration platform with a notebook-style UI. Self-hosted instances default to TCP 6789 and historically have shipped without authentication. Exposed instances may reveal pipeline source, secrets, and provide an authenticated path to arbitrary code execution via custom blocks.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'mageai'],
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
        'references': ['https://github.com/mage-ai/mage-ai', 'https://docs.mage.ai/'],
    }

    def run(self):
        markers = (
            '<title>mage</title>',
        )
        for path in ('/', '/api/status'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            if any(m in body for m in markers):
                self.set_info(
                    severity='info',
                    reason="Mage AI Panel detected",
                    path=path,
                )
                return True
        return False

