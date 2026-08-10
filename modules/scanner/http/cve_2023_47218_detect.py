#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QNAP QTS/QuTS hero uninitialized quick.cgi (CVE-2023-47218)."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'QNAP QTS/QuTS - Uninitialized quick.cgi Detection (CVE-2023-47218)',
        'description': (
            'Detects an uninitialized QNAP NAS exposing /cgi-bin/quick/quick.cgi '
            '(CVE-2023-47218 command injection surface). Looks for HTTP 200 with '
            'firmware_info or a failure/801 response to a random func parameter.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'qnap', 'qts', 'nas', 'rce',
            'unauth', 'vuln',
        ],
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/qnap_cve_2023_47218_rce'],
            },
        },
        'references': [
            'https://www.qnap.com/en/security-advisory/qsa-23-57',
            'https://www.rapid7.com/blog/post/2024/02/13/cve-2023-47218-qnap-qts-and-quts-hero-unauthenticated-command-injection-fixed',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-47218',
        ],
        'cve': 'CVE-2023-47218',
    }

    def run(self):
        token = secrets.token_hex(4)
        path = f'/cgi-bin/quick/quick.cgi?func={token}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if '<firmware_info>' in body or ('failure' in body and '801' in body):
            self.set_info(
                severity='critical',
                reason='QNAP uninitialized quick.cgi exposed (CVE-2023-47218 surface)',
                path=path,
            )
            return True
        return False
