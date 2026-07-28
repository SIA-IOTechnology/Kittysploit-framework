#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Teampass ldap."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Teampass LDAP Debug Config - Detect',
        'description': 'Teampass ldap.debug.txt config was detected. This file is generated on "/files/ldap.debug.txt" for versions earlier than 3.0.0.0 when utilizing the "Test current configuration" in LDAP settings.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'teampass', 'ldap', 'logs', 'vuln'],
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
            'https://github.com/nilsteampassnet/TeamPass/commit/ea9838481a58879cdf3def31046955efcff5a546#diff-61809be6a8fff101e3748a0c7dfad90bR16',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/files/ldap.debug.txt', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/plain',)
        header_all = ('base_dn', 'search_base', 'bind_dn', 'bind_passwd',)
        if (any(m in headers for m in header_any)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='medium',
                reason="Teampass LDAP Debug Config detected",
                path='/files/ldap.debug.txt',
            )
            return True
        return False

