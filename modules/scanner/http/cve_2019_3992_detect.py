#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ELOG unauthenticated config disclosure (CVE-2019-3992)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ELOG - GetConfig Disclosure Detection (CVE-2019-3992)',
        'description': (
            'Detects CVE-2019-3992 by requesting /?cmd=GetConfig and looking for '
            'filename="export.txt" Content-Disposition.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'elog', 'info-disclosure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.2,
            'value': 0.8,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2019-3992'],
        'cve': 'CVE-2019-3992',
    }

    def run(self):
        path = '/?cmd=GetConfig'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = '\n'.join(f'{k}: {v}' for k, v in r.headers.items())
        if 'filename="export.txt"' in headers or "filename='export.txt'" in headers:
            self.set_info(
                severity='medium',
                reason='ELOG GetConfig disclosure (CVE-2019-3992)',
                path=path,
            )
            return True
        return False
