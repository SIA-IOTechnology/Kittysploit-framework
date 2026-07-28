#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Huawei Routers are vulnerable to authentication bypass because the default password of this router is the last."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Huawei Router - Authentication Bypass Detection',
        'description': "Huawei Routers are vulnerable to authentication bypass because the default password of this router is the last 8 characters of the device's serial number which exist on the back of the device.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'auth-bypass', 'router', 'edb', 'huawei', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/48310'],
    }

    def run(self):
        path = '/api/system/deviceinfo'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': 'application/json, text/javascript, */*; q=0.01', 'Referer': '{{BaseURL}}'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DeviceName', 'SerialNumber', 'HardwareVersion',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Huawei Router - Authentication Bypass detected', path=path)
            return True
        return False

