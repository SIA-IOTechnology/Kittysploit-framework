#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Splunk Enterprise web/API interface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_xml_response, is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Splunk Detection",
        "description": "Detects Splunk management REST API and login UI.",
        "author": ["KittySploit Team"],
        "severity": "medium",
        "tags": ["web", "scanner", "splunk", "siem", "observability", "panel"],
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

    port = OptPort(8000, "Splunk web port", True)

    def run(self):
        for path in ("/en-US/services/server/info", "/services/server/info", "/en-US/account/login"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            body = r.text or ""
            if is_xml_response(body) and ("splunk" in body.lower() or "servername" in body.lower()):
                self.set_info(severity="medium", reason="Splunk REST API detected", path=path)
                return True
            if is_html_response(r) and "splunk" in body.lower() and "login" in body.lower():
                self.set_info(severity="medium", reason="Splunk login UI detected", path=path)
                return True
        return False
