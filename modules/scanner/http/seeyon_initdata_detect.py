#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seeyon OA A6 initDataAssess."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seeyon OA A6 initDataAssess.jsp - Information Disclosure Detection',
        'description': "Seeyon OA A6 initDataAssess.jsp has leaked user sensitive information, attacker can use the obtained username to blast the user's password to enter the background for further attacks.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'seeyon', 'oa', 'info-leak', 'vuln'],
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
            'https://github.com/achuna33/MYExploit/blob/8ffbf7ee60cbd77ad90b0831b93846aba224ab29/src/main/java/com/achuna33/Controllers/SeeyonController.java',
            'https://github.com/Threekiii/Awesome-POC/blob/master/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E8%87%B4%E8%BF%9COA%20A6%20initDataAssess.jsp%20%E7%94%A8%E6%88%B7%E6%95%8F%E6%84%9F%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2.md',
        ],
    }

    def run(self):
        path = '/yyoa/assess/js/initDataAssess.jsp'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('personList', 'personHash.Add',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='Seeyon OA A6 initDataAssess.jsp - Information Disclosure detected', path=path)
            return True
        return False

