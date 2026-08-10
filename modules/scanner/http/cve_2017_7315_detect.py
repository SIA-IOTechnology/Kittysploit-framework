#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HUMAX GatewaySettings.bin unauthenticated download (CVE-2017-7315)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HUMAX Gateway - Backup Download Detection (CVE-2017-7315)',
        'description': (
            'Detects CVE-2017-7315 by requesting /view/basic/GatewaySettings.bin without '
            'authentication and matching download headers.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'humax', 'router', 'info-leak', 'unauth', 'vuln',
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
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'credential_leak', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-7315',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-7316',
        ],
        'cve': 'CVE-2017-7315',
    }

    def run(self):
        path = '/view/basic/GatewaySettings.bin'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = {k.lower(): v for k, v in r.headers.items()}
        ctype = headers.get('content-type', '')
        cdisp = headers.get('content-disposition', '')
        if 'application/x-download' in ctype and 'GatewaySettings.bin' in cdisp:
            self.set_info(
                severity='high',
                reason='HUMAX GatewaySettings.bin download (CVE-2017-7315)',
                path=path,
            )
            return True
        return False
