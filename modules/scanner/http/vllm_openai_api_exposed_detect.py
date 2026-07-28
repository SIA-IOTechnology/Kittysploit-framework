#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects a vLLM inference server exposing its OpenAI-compatible API without authentication."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vLLM OpenAI-Compatible API - Unauthenticated Exposure Detection',
        'description': 'Detects a vLLM inference server exposing its OpenAI-compatible API without authentication. The /v1/models endpoint returns the list of served models and is reachable by any unauthenticated client, allowing model enumeration and unauthorized inference (resource abuse / cost and information exposure). vLLM does not enable an API key by default; it is only enforced when the server is started with --api-key.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'vllm', 'llm', 'ai', 'api', 'unauth', 'misconfig'],
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
            'https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html',
            'https://github.com/vllm-project/vllm',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/v1/models', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('"object"\\s*:\\s*"list"', '"owned_by"\\s*:\\s*"vllm', '"max_model_len"',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="vLLM OpenAI-Compatible API - Unauthenticated Exposure detected",
                path='/v1/models',
            )
            return True
        return False

