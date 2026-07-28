#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rocket."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Rocket.Chat <3.9.1 - Information Disclosure Detection',
        'description': 'Rocket.Chat through 3.9.1 is susceptible to information disclosure. An attacker can enumerate email addresses via the password reset function and thus potentially access sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'packetstorm', 'rocketchat', 'rocket.chat', 'vuln'],
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
            'https://trovent.io/security-advisory-2010-01',
            'https://trovent.github.io/security-advisories/TRSA-2010-01/TRSA-2010-01.txt',
            'http://www.openwall.com/lists/oss-security/2021/01/07/1',
            'http://packetstormsecurity.com/files/160845/Rocket.Chat-3.7.1-Email-Address-Enumeration.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-28208',
        ],
        'cve': 'CVE-2020-28208',
    }

    def run(self):
        path = '/api/v1/method.callAnon/sendForgotPasswordEmail'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Origin': '{{BaseURL}}', 'Content-Type': 'application/json'}, data='{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"sendForgotPasswordEmail\\",\\"params\\":[\\"user@local.email\\"],\\"id\\":\\"3\\"}"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"result\\":false', '"success":true',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='Rocket.Chat <3.9.1 - Information Disclosure detected', path=path)
            return True
        return False

