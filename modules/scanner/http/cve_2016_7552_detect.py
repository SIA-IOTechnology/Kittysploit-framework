#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trend Micro Threat Discovery Appliance 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Trend Micro Threat Discovery Appliance 2.6.1062r1 - Authentication Bypass Detection',
        'description': 'Trend Micro Threat Discovery Appliance 2.6.1062r1 is vulnerable to a directory traversal vulnerability when processing a session_id cookie, which allows a remote, unauthenticated attacker to delete arbitrary files as root. This can be used to bypass authentication or cause a DoS.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'msf', 'lfi', 'auth', 'bypass', 'trendmicro', 'vuln'],
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
            'https://gist.github.com/malerisch/5de8b408443ee9253b3954a62a8d97b4',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-7552',
            'https://github.com/rapid7/metasploit-framework/pull/8216/commits/0f07875a2ddb0bfbb4e985ab074e9fc56da1dcf6',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2016-7552',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/logoff.cgi', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Memory map',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Trend Micro Threat Discovery Appliance 2.6.1062r1 - Authentication Bypass detected",
                path='/cgi-bin/logoff.cgi',
            )
            return True
        return False

