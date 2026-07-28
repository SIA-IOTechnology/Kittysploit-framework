#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This template can be used to detect a Laravel debug information leak by making a POST-based request."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Laravel Debug Info Leak Detection',
        'description': 'This template can be used to detect a Laravel debug information leak by making a POST-based request.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfig', 'laravel', 'debug', 'infoleak', 'vuln'],
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
        'references': ['https://github.com/dem0ns/improper/blob/master/laravel/5_debug/1.png'],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='')
        if not r or r.status_code != 405:
            return False
        body = r.text or ""
        body_any = ('DB_PASSWORD', 'REDIS_PASSWORD', 'MAIL_PASSWORD', 'ALIYUN_ACCESSKEYSECRET', 'ALIYUN_ACCESSKEYID', 'SMS_AUTH_TOKEN', 'APP_KEY',)
        body_all = ('vendor/laravel/framework/src/Illuminate/', 'MethodNotAllowedHttpException',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(severity='medium', reason='Laravel Debug Info Leak detected', path=path)
            return True
        return False

