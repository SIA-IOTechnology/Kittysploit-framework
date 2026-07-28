#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This vulnerability allows an attacker to bypass authentication in the ReCrystallize Server application by mani."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ReCrystallize Server - Authentication Bypass Detection',
        'description': "This vulnerability allows an attacker to bypass authentication in the ReCrystallize Server application by manipulating the 'AdminUsername' cookie. This gives the attacker administrative access to the application's functionality, even when the default password has been changed.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'recrystallize', 'auth-bypass', 'cve2024', 'vuln'],
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
            'https://preview.sensepost.com/blog/2024/from-discovery-to-disclosure-recrystallize-server-vulnerabilities/',
            'https://sensepost.com/blog/2024/from-discovery-to-disclosure-recrystallize-server-vulnerabilities/',
            'https://www.recrystallize.com/merchant/ReCrystallize-Server-for-Crystal-Reports.htm',
            'https://github.com/Ostorlab/KEV',
        ],
        'cve': 'CVE-2024-26331',
    }

    def run(self):
        r = self.http_request(method="GET", path='/Admin/Admin.aspx', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ReCrystallize Server Administration', 'License Status:', 'System Info</a>',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="ReCrystallize Server - Authentication Bypass detected",
                path='/Admin/Admin.aspx',
            )
            return True
        return False

