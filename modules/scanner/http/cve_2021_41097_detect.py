#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Aurelia-path before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Aurelia-Path < 1.1.7 - Prototype Pollution Detection',
        'description': 'Aurelia-path before 1.1.7 contains a prototype pollution caused by parsing malicious URL parameters, letting attackers modify Object.prototype, exploit requires the application to parse user-controlled URLs.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'aurelia', 'prototype-pollution', 'javascript', 'passive'],
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
            'https://github.com/aurelia/path/issues/44',
            'https://security.snyk.io/vuln/SNYK-JS-AURELIAPATH-1579475',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41097',
        ],
        'cve': 'CVE-2021-41097',
    }

    def run(self):
        r = self.http_request(method="GET", path='/blog/?__proto__[polluted]=polluted', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('1.1.0', '1.1.1', '1.1.2', '1.1.3', '1.1.4', '1.1.5', '1.1.6',)
        body_all = ('aurelia-path', 'parseQueryString',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Aurelia-Path < 1.1.7 - Prototype Pollution detected",
                path='/blog/?__proto__[polluted]=polluted',
            )
            return True
        return False

