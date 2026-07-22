#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Ollama local LLM API."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Ollama Detection",
        "description": "Detects Ollama model API via /api/tags endpoint.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "ollama", "llm", "ai", "panel"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
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
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'ai_panel', 'from_detail': ''},
                                   {'capability': 'misconfig_surface', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['scanner/http/ollama_api_verify',
                                 'scanner/http/openwebui_unauth_verify',
                                 'scanner/http/comfyui_unauth_verify',
                                 'scanner/http/mlflow_unauth_verify']},
    },
    }

    port = OptPort(11434, "Ollama API port", True)

    def run(self):
        r = self.http_request(method="GET", path="/api/tags", allow_redirects=False)
        data, err = parse_json_response(r) if r else (None, "bad_status")
        if err or not data:
            return False
        models = data.get("models")
        if isinstance(models, list):
            self.set_info(
                severity="high",
                reason="Ollama API exposed",
                model_count=len(models),
            )
            return True
        return False
