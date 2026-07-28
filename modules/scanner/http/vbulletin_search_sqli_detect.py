#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vBulletin 4 is vulnerable to an SQL injection vulnerability, which may allow an attacker can execute malicious."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBulletin `Search.php` - SQL Injection Detection',
        'description': "vBulletin 4 is vulnerable to an SQL injection vulnerability, which may allow an attacker can execute malicious SQL statements that control a web application's database server.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vbulletin', 'sqli', 'vuln'],
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
            'https://www.exploit-db.com/exploits/17314',
            'https://web.archive.org/web/20181129123620/https://j0hnx3r.org/vbulletin-4-x-sql-injection-vulnerability/',
        ],
    }

    def run(self):
        path = '/search.php'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='contenttypeid=7&do=process&humanverify=1&cat[]=-1%27\n')
        if not r or r.status_code not in (200, 503):
            return False
        body = r.text or ""
        body_all = ('type=dberror', 'MySQL Error',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='vBulletin `Search.php` - SQL Injection detected', path=path)
            return True
        return False

