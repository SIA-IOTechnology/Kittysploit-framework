#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Brickcom IP cameras accessible using default credentials (admin/admin)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Brickcom Camera - Default Login Detection',
        'description': 'Detected Brickcom IP cameras accessible using default credentials (admin/admin). Successful authentication exposed full camera configuration, live video streams, LED control, and network settings to remote attackers.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'iot', 'camera', 'default-login'],
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
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.brickcom.com/support/faq_contents.php?id=48',
            'https://cxsecurity.com/issue/WLB-2026020031',
        ],
    }

    def run(self):
        path = '/index_mjpg.html'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Authorization': 'Basic YWRtaW46YWRtaW4=', 'Connection': 'close'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ("var viewer='admin'", 'Brickcom Corporation', 'wledctl.cgi',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Brickcom Camera - Default Login detected', path=path)
            return True
        return False

