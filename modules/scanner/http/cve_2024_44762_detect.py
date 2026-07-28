#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Usermin version 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Usermin 2.100 - Username Enumeration Detection',
        'description': 'Usermin version 2.100 and below is susceptible to username enumeration via the password change functionality. An attacker can determine valid usernames by analyzing the response messages from the password change endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'usermin', 'webmin', 'exposure', 'usernames', 'vuln'],
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
            'https://www.exploit-db.com/exploits/52254',
            'https://www.webmin.com/usermin.html',
            'https://senscybersecurity.nl/cve-2024-44762-explained/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-44762',
        ],
        'cve': 'CVE-2024-44762',
    }

    def run(self):
        path = '/password_change.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': '{{BaseURL}}/password_change.cgi'}, data='user=admin&pam=&expired=2&old=fakePassword&new1=password&new2=password\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Failed to change password: The current password is incorrect', 'Your login name was not found in the password file',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='Usermin 2.100 - Username Enumeration detected', path=path)
            return True
        return False

