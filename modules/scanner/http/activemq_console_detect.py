#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Apache ActiveMQ web console."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ActiveMQ Console Detection",
        "description": "Detects ActiveMQ web admin console on port 8161.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "activemq", "messaging", "java", "panel"],
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
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    port = OptPort(8161, "ActiveMQ web console port", True)

    def run(self):
        for path in ("/admin/", "/api/jolokia/", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401, 403):
                continue
            body = (r.text or "").lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            if "activemq" in body or "apache activemq" in body or "jolokia" in body:
                severity = "high" if r.status_code == 200 and "/admin" in path else "medium"
                self.set_info(severity=severity, reason="ActiveMQ console/API detected", path=path)
                return True
            if is_html_response(r) and "jolokia" in headers.get("www-authenticate", "").lower():
                self.set_info(severity="medium", reason="ActiveMQ Jolokia endpoint detected", path=path)
                return True
        return False
