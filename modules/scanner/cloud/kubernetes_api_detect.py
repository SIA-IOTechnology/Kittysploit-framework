#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection API Kubernetes exposée."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import (
    looks_like_kubernetes_health,
    looks_like_kubernetes_resource_list,
    looks_like_kubernetes_version,
    parse_json_response,
)


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Kubernetes API detection",
        "description": "Detects exposed Kubernetes API (version, namespaces, healthz).",
        "author": ["KittySploit Team"],
        "severity": "high",
        "modules": [],
        "tags": ["cloud", "scanner", "kubernetes", "k8s", "api", "cluster"],
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
        'chain':         {'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        for path in ["/version", "/api/v1", "/api/v1/namespaces", "/healthz", "/readyz"]:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401, 403):
                continue
            if path in ("/healthz", "/readyz"):
                if r.status_code == 200 and looks_like_kubernetes_health(r.text or "", r):
                    self.set_info(severity="high", reason=f"Kubernetes health at {path}")
                    return True
                continue
            data, err = parse_json_response(r)
            if err or not data:
                continue
            if path == "/version" and looks_like_kubernetes_version(data):
                self.set_info(severity="high", reason=f"Kubernetes API at {path}")
                return True
            if path.startswith("/api/v1") and looks_like_kubernetes_resource_list(data):
                self.set_info(severity="high", reason=f"Kubernetes API at {path}")
                return True
        return False
