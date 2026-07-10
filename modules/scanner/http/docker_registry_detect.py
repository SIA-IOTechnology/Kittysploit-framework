#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Docker Registry (API v2)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Docker Registry detection",
        "description": "Detects Docker Registry API v2 (image listing possible).",
        "author": "KittySploit Team",
        "severity": "low",
        "modules": [],
        "tags": ["web", "scanner", "docker", "registry", "container"],
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
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        r = self.http_request(method="GET", path="/v2/", allow_redirects=False)
        if not r:
            return False
        h = {k.lower(): v for k, v in r.headers.items()}
        if r.status_code == 200 and h.get("docker-distribution-api-version"):
            self.set_info(severity="low", reason="Docker Registry v2 API")
            return True
        if r.status_code == 200 and ("v2" in r.text or "docker" in r.text.lower()):
            self.set_info(severity="low", reason="Docker Registry v2 API")
            return True
        return False
