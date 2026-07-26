#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed HashiCorp Consul API/UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Consul Detection",
        "description": "Detects unauthenticated Consul agent and status endpoints.",
        "author": ["KittySploit Team"],
        "severity": "high",
        "tags": ["web", "scanner", "consul", "hashicorp", "misconfig"],
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
        'chain':         {'produces_capabilities': [{'capability': 'devops_panel', 'from_detail': ''},
                                   {'capability': 'misconfig_surface', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['auxiliary/scanner/http/debug_info_leak',
                                 'scanner/cloud/kubernetes_api_detect']},
    },
    }

    def run(self):
        for path in ("/v1/agent/self", "/v1/status/leader", "/ui/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 301, 302):
                continue
            body = (r.text or "").lower()
            if "consul" in body or "raft" in body or "datacenter" in body and "config" in body:
                severity = "high" if path.startswith("/v1/") and r.status_code == 200 else "info"
                self.set_info(severity=severity, reason="Consul service detected", path=path)
                return True
        return False
