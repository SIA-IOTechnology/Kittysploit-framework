#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Unified Call Manager is vulnerable to username enumeration."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco Unified Communications Manager - User Enumeration Detection',
        'description': 'Cisco Unified Call Manager is vulnerable to username enumeration. This template enumerates valid usernames and emails from the Cisco UCM UDS API.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'cisco', 'ucm', 'enum', 'users', 'xml', 'cucm', 'unauth', 'vuln'],
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://developer.cisco.com/site/user-data-services/develop-and-test/api-reference/#users',
            'https://www.n00py.io/2022/01/unauthenticated-dumping-of-usernames-via-cisco-unified-call-manager-cucm/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/cucm-uds/users', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('application/xml', 'text/xml',)
        body_all = ('<users', '<username>', '<lastname>', '<phonenumber>',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Cisco Unified Communications Manager - User Enumeration detected",
                path='/cucm-uds/users',
            )
            return True
        return False

