#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected misconfigured Expect-CT headers: max-age is 0 (ineffective) and enforce directive is missing."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Expect-CT Header - Misconfigured Detection',
        'description': 'Detected misconfigured Expect-CT headers: max-age is 0 (ineffective) and enforce directive is missing',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'headers', 'expect-ct'],
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
            'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT',
            'https://scotthelme.co.uk/a-new-security-header-expect-ct/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        # Only the Expect-CT header value — avoid matching max-age=/enforce elsewhere.
        expect_ct = ""
        for key, value in (r.headers or {}).items():
            if str(key).lower() == "expect-ct":
                expect_ct = str(value or "").lower()
                break
        if not expect_ct:
            return False
        # Misconfig: present but ineffective (max-age=0) and/or missing enforce.
        if "max-age=0" in expect_ct.replace(" ", "") or "enforce" not in expect_ct:
            self.set_info(
                severity="info",
                reason="Expect-CT Header - Misconfigured detected",
                path="/",
                expect_ct=expect_ct[:200],
            )
            return True
        return False

