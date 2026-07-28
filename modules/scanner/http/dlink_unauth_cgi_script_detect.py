#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability has been identified in the D-Link DNS series network storage devices, allowing for the exposur."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DNS Series  CGI Script - Unauthenticated Detection',
        'description': 'A vulnerability has been identified in the D-Link DNS series network storage devices, allowing for the exposure of sensitive device information to unauthorized actors. This vulnerability is due to an unauthenticated access flaw in the info.cgi script, which can be exploited via a simple HTTP GET request, affecting over 920,000 devices on the Internet.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'unauth', 'dlink', 'misconfig', 'vuln'],
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
        'references': ['https://github.com/netsecfish/info_cgi'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/info.cgi', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Product=', 'Version=', 'Model=',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="D-Link DNS Series  CGI Script - Unauthenticated detected",
                path='/cgi-bin/info.cgi',
            )
            return True
        return False

