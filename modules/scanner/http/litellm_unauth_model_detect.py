#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LiteLLM proxy was detected with anonymous access to the model listing API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LiteLLM Proxy - Model Exposure Detection',
        'description': 'LiteLLM proxy was detected with anonymous access to the model listing API. LiteLLM proxies that ship without `general_settings.master_key` (or with the key disabled) expose the configured upstream model catalog via /v1/models and /model/info — revealing which OpenAI / Anthropic / Azure / Bedrock / local-LLM endpoints are wired in, often along with their litellm_params routing config, and frequently leaving /chat/completions and /embeddings reachable without any bearer token.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'litellm', 'llm', 'ai', 'misconfig', 'exposure'],
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
            'https://docs.litellm.ai/docs/proxy/virtual_keys',
            'https://docs.litellm.ai/docs/proxy/configs',
            'https://github.com/BerriAI/litellm',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/model/info', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/json',)
        body_all = (':',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="LiteLLM Proxy - Model Exposure detected",
                path='/model/info',
            )
            return True
        return False

