#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Vercel-hosted sites via platform headers."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Vercel Detection",
        "description": "Detects Vercel edge/deploy platform response headers.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "vercel", "cdn", "saas", "hosting"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals'],
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        host = str(self.target or "").lower()
        if host.endswith(".vercel.app") or host.endswith(".now.sh"):
            self.set_info(severity="info", reason="Vercel hostname detected", host=host)
            return True

        r = self.http_request(method="GET", path="/", allow_redirects=False)
        if not r:
            return False
        headers = {k.lower(): v for k, v in r.headers.items()}
        if any(key in headers for key in ("x-vercel-id", "x-vercel-cache", "x-vercel-mitigated")):
            self.set_info(severity="info", reason="Vercel platform headers detected")
            return True
        if "server" in headers and "vercel" in headers["server"].lower():
            self.set_info(severity="info", reason="Vercel server header detected")
            return True
        return False
