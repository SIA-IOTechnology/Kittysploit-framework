#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect ClickHouse HTTP interface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "ClickHouse Detection",
        "description": "Detects ClickHouse /ping and HTTP query interface.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "clickhouse", "database", "analytics", "panel"],
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
        'chain':         {'produces_capabilities': [{'capability': 'devops_panel', 'from_detail': ''},
                                   {'capability': 'admin_surface', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['auxiliary/scanner/http/login_page_detector',
                                 'scanner/http/swagger_detect']},
    },
    }

    port = OptPort(8123, "ClickHouse HTTP port", True)

    def run(self):
        for path in ("/ping", "/?query=SELECT%201"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 401, 403):
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = (r.text or "").strip()
            if "x-clickhouse" in headers or body.lower().startswith("ok"):
                severity = "high" if r.status_code == 200 and path.startswith("/?query") else "medium"
                self.set_info(severity=severity, reason="ClickHouse HTTP API detected", path=path)
                return True
        return False
