#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected PyTorch TorchServe, a model-serving framework for PyTorch models."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PyTorch TorchServe - Detect',
        'description': 'Detected PyTorch TorchServe, a model-serving framework for PyTorch models. The inference API (default port 8080) answers GET /ping with {"status":"Healthy"} and exposes /api-description; the management API (default port 8081) lists registered models at GET /models. An exposed management API permits unauthenticated model registration and scaling and discloses the served model names.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'torchserve', 'pytorch', 'ai', 'llm', 'inference'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
        'references': ['https://github.com/pytorch/serve', 'https://pytorch.org/serve/'],
    }

    def run(self):
        for path in ('/api-description', '/models', '/ping'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_markers = ('apiDescription\\', 'operationId\\', ') || contains_all(body,', 'models\\', 'modelName\\', 'status\\', 'application/json')
            if any(m in body for m in body_markers):
                self.set_info(
                    severity='info',
                    reason="PyTorch TorchServe detected",
                    path=path,
                )
                return True
        return False

