#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Open WebUI LLM chat interface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response, is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Open WebUI Detection",
        "description": "Detects Open WebUI config API and login UI.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "openwebui", "llm", "ai", "panel"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
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

    def run(self):
        for path in ("/api/config", "/api/v1/auths/signin", "/auth"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            data, err = parse_json_response(r) if path.startswith("/api") else (None, "skip")
            if not err and data and any(key in data for key in ("name", "version", "default_models", "status")):
                if "open webui" in str(data.get("name", "")).lower() or data.get("version"):
                    self.set_info(severity="high", reason="Open WebUI API detected", path=path)
                    return True
            body = (r.text or "").lower()
            if is_html_response(r) and ("open-webui" in body or "open webui" in body):
                self.set_info(severity="high", reason="Open WebUI login UI detected", path=path)
                return True
        return False
