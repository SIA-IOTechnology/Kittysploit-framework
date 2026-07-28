#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple vulnerabilities exist in Phoenix Contact CHARX SEC-3XXX AC Controller versions prior to 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Phoenix Contact CHARX SEC-3XXX AC Controller < 1.7.3 - Multiple Vulnerabilities Detection',
        'description': 'Multiple vulnerabilities exist in Phoenix Contact CHARX SEC-3XXX AC Controller versions prior to 1.7.3. Successful exploitation may allow attackers to bypass authentication, disclose sensitive information, or execute arbitrary code.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'phoenix-contact', 'charx', 'vuln'],
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
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1.0/web/retained-data', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('charging_controllers', 'system',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Phoenix Contact CHARX SEC-3XXX AC Controller < 1.7.3 - Multiple Vulnerabilities detected",
                path='/api/v1.0/web/retained-data',
            )
            return True
        return False

