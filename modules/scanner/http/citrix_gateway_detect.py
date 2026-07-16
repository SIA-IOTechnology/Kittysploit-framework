#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Citrix ADC / Gateway login surfaces."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Citrix Gateway Detection",
        "description": "Detects Citrix ADC/Gateway VPN and logon pages.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "citrix", "adc", "vpn", "gateway", "panel"],
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
        'chain':         {'produces_capabilities': [{'capability': 'identity_surface', 'from_detail': ''},
                                   {'capability': 'enterprise_panel', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': ['auxiliary/scanner/http/login_page_detector']},
    },
    }

    def run(self):
        for path in ("/vpn/index.html", "/logon/LogonPoint/index.html", "/cgi/login"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 302, 401):
                continue
            body = (r.text or "").lower()
            headers = {k.lower(): v for k, v in r.headers.items()}
            citrix_markers = (
                "citrix" in body,
                "netscaler" in body,
                "receiver" in body and "citrix" in body,
                "ns_af" in headers.get("set-cookie", "").lower(),
                "citrix" in headers.get("server", "").lower(),
            )
            if not any(citrix_markers):
                continue
            if is_html_response(r) or r.status_code in (302, 401):
                self.set_info(severity="medium", reason="Citrix Gateway/VPN surface detected", path=path)
                return True
        return False
