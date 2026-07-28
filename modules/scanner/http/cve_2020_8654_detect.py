#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EyesOfNetwork 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EyesOfNetwork 5.1-5.3 - SQL Injection/Remote Code Execution Detection',
        'description': 'EyesOfNetwork 5.1 to 5.3 contains SQL injection and remote code execution vulnerabilities. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site. See also CVE-2020-8655, CVE-2020-8656, CVE-2020-8657, and CVE-2020-9465.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'cisa', 'eyesofnetwork', 'rce', 'authenticated', 'msf', 'sqli', 'passive', 'vuln'],
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
            'https://github.com/h4knet/eonrce',
            'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/eyesofnetwork_autodiscovery_rce.rb',
            'https://github.com/EyesOfNetworkCommunity/eonweb/issues/50',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8654',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-8654',
    }

    def run(self):
        path = '/css/eonweb.css'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('EyesOfNetwork',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='high',
                reason='EyesOfNetwork 5.1-5.3 - SQL Injection/Remote Code Execution detected',
                path=path,
            )
            return True
        return False

