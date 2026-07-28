#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAVLINK WN530HG4 M30HG4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WAVLINK WN530HG4 - Improper Access Control Detection',
        'description': 'WAVLINK WN530HG4 M30HG4.V5030.191116 is susceptible to improper access control. An attacker can obtain usernames and passwords via view-source:http://IP_ADDRESS/set_safety.shtml?r=52300 and searching for [var syspasswd] and thereby possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wavlink', 'router', 'exposure', 'packetstorm', 'vuln'],
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
            'https://drive.google.com/file/d/1sTQdUc12aZvJRFeb5wp8AfPdUEkkU9Sy/view?usp=sharing',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-34047',
            'http://packetstormsecurity.com/files/167891/Wavlink-WN530HG4-Password-Disclosure.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-34047',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-34047',
    }

    def run(self):
        path = '/set_safety.shtml?r=52300'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('var syspasswd="', '<title>APP</title>',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='WAVLINK WN530HG4 - Improper Access Control detected', path=path)
            return True
        return False

