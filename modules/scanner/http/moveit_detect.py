#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Progress MOVEit Transfer web interface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "MOVEit Transfer Detection",
        "description": "Detects Progress MOVEit Transfer login and portal pages.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "moveit", "progress", "file-transfer", "panel"],
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        for path in ("/human.aspx", "/signon.aspx", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 302, 401):
                continue
            body = (r.text or "").lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            moveit_markers = (
                "moveit" in body,
                "progress moveit" in body,
                "signon.aspx" in body,
                "human.aspx" in body,
                "/moveitisapi/" in body,
            )
            if not any(moveit_markers):
                continue
            if is_html_response(r) and "moveit" not in body and "signon.aspx" not in body:
                continue
            self.set_info(
                severity="medium",
                reason="Progress MOVEit Transfer interface detected",
                path=path,
                server=headers.get("server", ""),
            )
            return True
        return False
