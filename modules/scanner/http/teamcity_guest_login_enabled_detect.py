#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TeamCity provides the ability to turn on the guest login allowing anonymous access to the TeamCity UI."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JetBrains TeamCity - Guest User Access Enabled Detection',
        'description': 'TeamCity provides the ability to turn on the guest login allowing anonymous access to the TeamCity UI.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfig', 'teamcity', 'jetbrains', 'vuln'],
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
            'https://ph33r.medium.com/misconfig-in-teamcity-panel-lead-to-auth-bypass-in-apache-org-exploit-146f6a1a4e2b',
            'https://www.jetbrains.com/help/teamcity/guest-user.html',
        ],
    }

    def run(self):
        path = '/guestLogin.html?guest=1'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('Location: /overview.html', 'TCSESSIONID=',)
        if any(m in headers for m in header_any):
            self.set_info(severity='high', reason='JetBrains TeamCity - Guest User Access Enabled detected', path=path)
            return True
        return False

