#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected the presence of HuggingFace Text Embeddings Inference (TEI), a toolkit for serving text embedding and."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HuggingFace TEI & TGI - Detect',
        'description': 'Detected the presence of HuggingFace Text Embeddings Inference (TEI), a toolkit for serving text embedding and re-ranking models, and HuggingFace Text Generation Inference (TGI), a Rust/Python toolkit for serving and deploying large language models.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'tei', 'tgi', 'llm'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/huggingface/text-embeddings-inference',
            'https://github.com/huggingface/text-generation-inference',
            'https://huggingface.co/docs/text-embeddings-inference/index',
        ],
    }

    def run(self):
        path = '/info'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"model_id"',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='info',
                reason='HuggingFace TEI & TGI detected',
                path=path,
            )
            return True
        return False

