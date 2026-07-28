#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected vLLM was a high-throughput LLM serving engine that exposed an OpenAI-compatible HTTP API on TCP 8000 ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vLLM OpenAI-Compatible Server - Detect',
        'description': 'Detected vLLM was a high-throughput LLM serving engine that exposed an OpenAI-compatible HTTP API on TCP 8000 with no authentication by default.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'tech', 'vllm', 'llm', 'ai', 'ml', 'openai'],
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
            'https://github.com/vllm-project/vllm',
            'https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('vLLM', '/v1/models', '/v1/chat/completions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="vLLM OpenAI-Compatible Server detected",
                path='/',
            )
            return True
        return False

