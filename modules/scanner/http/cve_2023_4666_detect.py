#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin does not validate signatures when creating them on the server from user input, allowing unauthentic."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Form-Maker < 1.15.20 - Unauthenticated Arbitrary File Upload Detection',
        'description': 'The plugin does not validate signatures when creating them on the server from user input, allowing unauthenticated users to create arbitrary files and lead to RCE.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'wpscan', 'cve2023', 'wordpress', 'wp-plugin', 'form-maker', 'passive', 'vkev', 'vuln'],
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
        'references': ['https://wpscan.com/vulnerability/c6597e36-02d6-46b4-89db-52c160f418be/'],
        'cve': 'CVE-2023-4666',
    }

    def run(self):
        path = '/wp-content/plugins/form-maker/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Form Maker by 10Web',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='Form-Maker < 1.15.20 - Unauthenticated Arbitrary File Upload detected',
                path=path,
            )
            return True
        return False

