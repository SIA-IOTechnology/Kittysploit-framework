#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects SGLang, a high-performance LLM serving framework that provides an OpenAI-compatible API (default port ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SGLang - Detect',
        'description': 'Detects SGLang, a high-performance LLM serving framework that provides an OpenAI-compatible API (default port 30000). This template identifies SGLang by checking for the unique /get_model_info endpoint (returning "model_path" and "is_generation") and Prometheus metrics prefixed with "sglang:". An unauthenticated server exposes inference access and reveals the underlying model path, which is extracted if found.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'sglang', 'llm'],
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
        'references': [
            'https://github.com/sgl-project/sglang',
            'https://docs.sglang.ai/backend/openai_api_completions.html',
        ],
    }

    def run(self):
        for path in ('/get_model_info', '/metrics'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_markers = ('sglang',)
            if any(m in body for m in body_markers):
                self.set_info(
                    severity='info',
                    reason="SGLang detected",
                    path=path,
                )
                return True
        return False

