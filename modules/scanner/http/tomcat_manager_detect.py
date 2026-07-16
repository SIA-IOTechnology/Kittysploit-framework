#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed Apache Tomcat Manager interface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Tomcat Manager Detection",
        "description": "Detects Tomcat /manager/html and host-manager interfaces.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "tomcat", "java", "panel", "misconfig"],
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
        'chain':         {'produces_capabilities': [{'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        for path in ("/manager/html", "/host-manager/html", "/manager/status"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = (r.text or "").lower()
            auth = headers.get("www-authenticate", "").lower()
            if "tomcat" in auth or "tomcat manager" in body or "manager app" in body:
                severity = "high" if r.status_code == 200 else "medium"
                self.set_info(severity=severity, reason="Tomcat Manager interface detected", path=path)
                return True
        return False
