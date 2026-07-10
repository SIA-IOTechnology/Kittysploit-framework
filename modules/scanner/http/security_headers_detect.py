#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Security headers that should ideally be present
SECURITY_HEADERS = [
    ("X-Frame-Options", "low", "Clickjacking protection"),
    ("X-Content-Type-Options", "low", "MIME sniffing protection"),
    ("X-XSS-Protection", "info", "Legacy XSS filter"),
    ("Strict-Transport-Security", "info", "HSTS"),
    ("Content-Security-Policy", "info", "CSP"),
    ("Referrer-Policy", "info", "Referrer leakage"),
    ("Permissions-Policy", "info", "Feature policy"),
]


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Security headers detection',
        'description': 'Detects missing HTTP security headers (X-Frame-Options, CSP, HSTS, etc.).',
        'author': 'KittySploit Team',
        'severity': 'low',
        'modules': [],
        'tags': ['web', 'scanner', 'security', 'headers', 'hardening'],
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
        if not r or r.status_code != 200:
            return False
        headers_lower = {k.lower(): k for k in r.headers}
        missing = []
        for header_name, _sev, desc in SECURITY_HEADERS:
            if header_name.lower() not in headers_lower:
                missing.append(header_name)
        if missing:
            self.set_info(severity="low", reason=f"Missing headers: {', '.join(missing)}")
            return True
        return False
