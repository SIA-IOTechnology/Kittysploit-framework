#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect ComfyUI generative AI workflow interface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response, is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ComfyUI Detection",
        "description": "Detects ComfyUI system stats API and web UI.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "comfyui", "ai", "diffusion", "panel"],
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

    port = OptPort(8188, "ComfyUI default port", True)

    def run(self):
        r = self.http_request(method="GET", path="/system_stats", allow_redirects=False)
        data, err = parse_json_response(r) if r else (None, "bad_status")
        if not err and data and any(key in data for key in ("system", "devices", "ram_total")):
            self.set_info(severity="high", reason="ComfyUI system_stats API exposed")
            return True

        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if r and r.status_code == 200 and is_html_response(r):
            body = (r.text or "").lower()
            if "comfyui" in body or "comfy-ui" in body:
                self.set_info(severity="high", reason="ComfyUI web UI detected")
                return True
        return False
