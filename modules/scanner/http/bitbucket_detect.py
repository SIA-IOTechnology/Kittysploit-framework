#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Atlassian Bitbucket Server/Data Center."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Bitbucket Detection",
        "description": "Detects Bitbucket REST API and login UI.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "bitbucket", "atlassian", "devops", "panel"],
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
        for path in ("/rest/api/1.0/application-properties", "/login", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            data, err = parse_json_response(r) if "rest/api" in path else (None, "skip")
            if not err and data and ("version" in data or "buildDate" in data):
                self.set_info(
                    severity="info",
                    reason="Bitbucket REST API detected",
                    path=path,
                    version=str(data.get("version") or ""),
                )
                return True
            body = (r.text or "").lower()
            if "bitbucket" in body and ("log in" in body or "atlassian" in body):
                self.set_info(severity="info", reason="Bitbucket login UI detected", path=path)
                return True
        return False
