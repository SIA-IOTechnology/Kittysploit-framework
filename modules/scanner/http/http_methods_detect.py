#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Methods that are often considered risky when allowed on web root
RISKY_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'HTTP methods detection',
        'description': 'Detects allowed HTTP methods (via Allow header or OPTIONS). Risky methods may indicate misconfiguration.',
        'author': 'KittySploit Team',
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'http', 'methods', 'options', 'allow'],
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
        r = self.http_request(method="OPTIONS", path="/", allow_redirects=False)
        if not r:
            return False
        allow = r.headers.get("Allow")
        if not allow:
            return False
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        if not methods:
            return False
        risky = [m for m in methods if m in RISKY_METHODS]
        if risky:
            self.set_info(severity="low", reason=f"Allowed: {', '.join(methods)} (risky: {', '.join(risky)})")
        else:
            self.set_info(severity="info", reason=f"Allowed methods: {', '.join(methods)}")
        return True
