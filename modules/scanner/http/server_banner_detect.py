#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection bannières serveur / versions exposées."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Server banner detection",
        "description": "Detects revealing Server or X-Powered-By headers (version disclosure).",
        "author": "KittySploit Team",
        "severity": "info",
        "modules": [],
        "tags": ["web", "scanner", "banner", "version", "disclosure", "headers"],
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
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if not r:
            return False
        headers_lower = {k.lower(): k for k in r.headers}
        revealed = []
        if "server" in headers_lower:
            v = r.headers.get(headers_lower["server"], "")
            if v and v.strip():
                revealed.append(f"Server: {v}")
        if "x-powered-by" in headers_lower:
            v = r.headers.get(headers_lower["x-powered-by"], "")
            if v and v.strip():
                revealed.append(f"X-Powered-By: {v}")
        if "x-aspnet-version" in headers_lower:
            v = r.headers.get(headers_lower["x-aspnet-version"], "")
            if v and v.strip():
                revealed.append(f"X-AspNet-Version: {v}")
        if revealed:
            self.set_info(severity="info", reason="; ".join(revealed))
            return True
        return False
