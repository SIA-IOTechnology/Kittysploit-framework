#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPNEGO stands for Simple and Protected GSSAPI Negotiation Mechanism."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SPNEGO - Detect',
        'description': 'SPNEGO stands for Simple and Protected GSSAPI Negotiation Mechanism. It is a protocol used for secure authentication and negotiation between client and server applications in a network environment. SPNEGO is based on the Generic Security Services Application Programming Interface (GSSAPI) framework.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misc', 'miscellaneous', 'windows', 'spnego', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://www.ibm.com/docs/en/was-liberty/core?topic=authentication-single-sign-http-requests-using-spnego-web',
            'https://arstechnica.com/information-technology/2022/12/critical-windows-code-execution-vulnerability-went-undetected-until-now/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        header_any = ('www-authenticate: negotiate',)
        if (any(m in headers for m in header_any)):
            self.set_info(
                severity='info',
                reason="SPNEGO detected",
                path='/',
            )
            return True
        return False

