#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drupal Coder module coder_upgrade.run.php exposure (SA-CONTRIB-2016-039)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drupal Coder - coder_upgrade.run.php Exposure Detection',
        'description': (
            'Soft-detects exposed Drupal Coder upgrade script at '
            '/sites/all/modules/coder/coder_upgrade/scripts/coder_upgrade.run.php.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'drupal', 'coder', 'rce', 'exposure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.2,
            'value': 0.7,
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
            'https://www.drupal.org/node/2761189',
        ],
    }

    def run(self):
        for base in ('', '/drupal'):
            path = f'{base}/sites/all/modules/coder/coder_upgrade/scripts/coder_upgrade.run.php'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r:
                continue
            body = r.text or ''
            if 'file parameter is not set' in body or 'No path to parameter file' in body:
                self.set_info(
                    severity='high',
                    reason='Drupal Coder upgrade script exposed',
                    path=path,
                )
                return True
        return False
