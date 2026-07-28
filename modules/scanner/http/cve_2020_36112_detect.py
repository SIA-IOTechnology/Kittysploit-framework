#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CSE Bookstore version 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CSE Bookstore 1.0 - SQL Injection Detection',
        'description': 'CSE Bookstore version 1.0 is vulnerable to time-based blind, boolean-based blind and OR error-based SQL injection in pubid parameter in bookPerPub.php. A successful exploitation of this vulnerability will lead to an attacker dumping the entire database.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'sqli', 'cse', 'edb', 'tenable', 'cse_bookstore_project', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/49314',
            'https://www.tenable.com/cve/CVE-2020-36112',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-36112',
            'https://github.com/StarCrossPortal/scalpel',
            'https://github.com/anonymous364872/Rapier_Tool',
        ],
        'cve': 'CVE-2020-36112',
    }

    def run(self):
        path = "/ebook/bookPerPub.php?pubid=4'"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('get book price failed! You have an error in your SQL syntax', "Can't retrieve data You have an error in your SQL syntax",)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='CSE Bookstore 1.0 - SQL Injection detected', path=path)
            return True
        return False

