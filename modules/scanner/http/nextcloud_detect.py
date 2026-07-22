#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Nextcloud file sync and collaboration instance."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Nextcloud Detection",
        "description": "Detects Nextcloud status endpoint and login UI.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "nextcloud", "collaboration", "saas", "panel"],
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
        r = self.http_request(method="GET", path="/status.php", allow_redirects=False)
        data, err = parse_json_response(r) if r else (None, "bad_status")
        if not err and data and "nextcloud" in str(data.get("productname", "")).lower():
            self.set_info(
                severity="info",
                reason="Nextcloud status endpoint detected",
                version=str(data.get("versionstring") or ""),
            )
            return True

        r = self.http_request(method="GET", path="/login", allow_redirects=False)
        if r and r.status_code in (200, 302):
            body = (r.text or "").lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            if "nextcloud" in body or "nextcloud" in headers.get("x-powered-by", ""):
                self.set_info(severity="info", reason="Nextcloud login UI detected")
                return True
        return False
