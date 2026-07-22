#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Apache Struts2 framework indicators."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import is_html_response


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache Struts Detection",
        "description": "Detects Struts2 action extensions and OGNL error fingerprints.",
        "author": ["KittySploit Team"],
        "severity": "info",
        "tags": ["web", "scanner", "struts", "apache", "java", "ognl"],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 3,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals'],
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
        for path in ("/index.action", "/login.action", "/struts/webconsole.html"):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r:
                continue
            body = (r.text or "").lower()
            if is_html_response(r):
                if "struts" in body and (".action" in path or "webconsole" in path):
                    self.set_info(severity="info", reason="Apache Struts endpoint detected", path=path)
                    return True
            markers = ("ognl", "xwork", "struts2", "there is no action mapped")
            if any(marker in body for marker in markers):
                self.set_info(severity="info", reason="Apache Struts/OGNL indicator detected", path=path)
                return True
        return False
