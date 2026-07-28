#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed Google Agent-to-Agent protocol agent cards."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Google A2A Agent Card - Enumeration Detection',
        'description': "Detected exposed Google Agent-to-Agent protocol agent cards. The agent-card.json file advertises an AI agent's capabilities, supported skills, authentication requirements, and endpoint URLs.",
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'enum', 'a2a', 'google', 'ai', 'agent'],
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
        'references': ['https://huggingface.co/blog/1bo/a2a-protocol-explained', 'https://github.com/google/A2A'],
    }

    def run(self):
        for path in ('/.well-known/agent-card.json', '/.well-known/agent.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('application/json',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='info',
                    reason="Google A2A Agent Card - Enumeration detected",
                    path=path,
                )
                return True
        return False

