#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect JetBrains TeamCity CI server."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "TeamCity Detection",
        "description": "Detects TeamCity REST API and login UI.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "teamcity", "jetbrains", "ci", "devops", "panel"],
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

    port = OptPort(8111, "TeamCity HTTP port", True)

    def run(self):
        for path in ("/app/rest/server", "/login.html", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            if "teamcity-version" in headers or "teamcity-node-id" in headers:
                self.set_info(
                    severity="info",
                    reason="TeamCity server detected",
                    path=path,
                    version=headers.get("teamcity-version", ""),
                )
                return True
            data, err = parse_json_response(r) if path.endswith("/server") else (None, "skip")
            if not err and data and str(data.get("version") or data.get("buildNumber") or ""):
                self.set_info(severity="info", reason="TeamCity REST API detected", path=path)
                return True
            body = (r.text or "").lower()
            if "teamcity" in body and ("log in to teamcity" in body or "teamcity-node" in body):
                self.set_info(severity="info", reason="TeamCity login UI detected", path=path)
                return True
        return False
