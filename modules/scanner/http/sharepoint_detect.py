#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Microsoft SharePoint and SharePoint Online."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response, is_xml_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SharePoint Detection",
        "description": "Detects SharePoint REST API, layouts, and Microsoft 365 markers.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "sharepoint", "microsoft", "collaboration", "panel"],
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
        host = str(self.target or "").lower()
        if host.endswith(".sharepoint.com"):
            self.set_info(severity="info", reason="SharePoint Online hostname detected", host=host)
            return True

        for path in ("/_api/web", "/_layouts/15/start.aspx", "/"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            headers = {k.lower(): v for k, v in r.headers.items()}
            if "microsoftsharepointteamservices" in headers or "sprequestguid" in headers:
                self.set_info(severity="info", reason="SharePoint server headers detected", path=path)
                return True
            data, err = parse_json_response(r) if path.startswith("/_api") else (None, "skip")
            if not err and data and any(key in data for key in ("d", "Title", "Url")):
                self.set_info(severity="info", reason="SharePoint REST API detected", path=path)
                return True
            body = r.text or ""
            if is_xml_response(body) and "sharepoint" in body.lower():
                self.set_info(severity="info", reason="SharePoint XML response detected", path=path)
                return True
        return False
