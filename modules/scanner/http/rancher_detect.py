#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Rancher Kubernetes management UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Rancher Detection",
        "description": "Detects Rancher management server API and dashboard.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "rancher", "kubernetes", "devops", "panel"],
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
        for path in ("/v3/settings/first-login", "/v3", "/dashboard/", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            data, err = parse_json_response(r) if path.startswith("/v3") else (None, "skip")
            if not err and data and ("type" in data or "data" in data):
                kind = str(data.get("type") or "").lower()
                if "setting" in kind or "collection" in kind or "apiroot" in kind:
                    self.set_info(severity="medium", reason="Rancher API detected", path=path)
                    return True
            body = (r.text or "").lower()
            if "rancher" in body and ("dashboard" in body or "ember" in body or "/v3/" in body):
                self.set_info(severity="medium", reason="Rancher dashboard detected", path=path)
                return True
        return False
