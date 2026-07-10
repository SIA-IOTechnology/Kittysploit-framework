#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection Swagger / OpenAPI exposé."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = [
    "/swagger",
    "/swagger/",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger-ui",
    "/swagger-ui.html",
    "/api-docs",
    "/api-docs/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "Swagger/OpenAPI detection",
        "description": "Detects exposed Swagger or OpenAPI documentation (API disclosure).",
        "author": "KittySploit Team",
        "severity": "low",
        "modules": [],
        "tags": ["web", "scanner", "swagger", "openapi", "api", "disclosure"],
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
         'api_surface_ready': True},
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
        for path in PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            t = r.text.lower()
            if "swagger" in t or "openapi" in t or '"paths":' in t or "api-docs" in path and ("{" in t or "yaml" in r.headers.get("content-type", "")):
                self.set_info(severity="low", reason=f"API docs exposed at {path}")
                return True
        return False
