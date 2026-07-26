#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect exposed GitLab instances."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "GitLab Detection",
        "description": "Detects GitLab login UI and version API exposure.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "gitlab", "devops", "panel"],
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
                                   {'capability': 'admin_surface', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['auxiliary/scanner/http/login_page_detector',
                                 'scanner/http/swagger_detect']},
    },
    }

    def run(self):
        for path in ("/api/v4/version", "/users/sign_in", "/-/readiness"):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r:
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = (r.text or "").lower()
            if "x-gitlab" in headers or "gitlab" in body or "sign in to gitlab" in body:
                version = ""
                if path == "/api/v4/version" and r.status_code == 200 and "version" in body:
                    version = r.text[:120]
                self.set_info(
                    severity="info",
                    reason="GitLab instance detected",
                    path=path,
                    version_hint=version,
                )
                return True
        return False
