#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AVTECH AVC798HA DVR is susceptible to information exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AVTECH AVC798HA DVR - Information Exposure Detection',
        'description': 'AVTECH AVC798HA DVR is susceptible to information exposure. CGI scripts in the /cgi-bin/nobody directory can be accessed without authentication. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'panel', 'dvr', 'exposure', 'avtech'],
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
                'confidence_min': {
                },
                'confidence_min_any': {
                },
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
                'option_bindings': {
                },
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['http://www.avtech.com.tw/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/nobody/Machine.cgi?action=get_capability', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = ()
        if False:
            self.set_info(
                severity='low',
                reason="AVTECH AVC798HA DVR - Information Exposure detected",
                path='/cgi-bin/nobody/Machine.cgi?action=get_capability',
            )
            return True
        return False

