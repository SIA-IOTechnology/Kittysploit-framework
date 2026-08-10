#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache OPTIONS Allow header memory leak / Optionsbleed (CVE-2017-9798)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache HTTPD - Optionsbleed Detection (CVE-2017-9798)',
        'description': (
            'Detects CVE-2017-9798 by sending repeated OPTIONS requests and looking for '
            'malformed Allow headers (double commas / numeric garbage).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'apache', 'info-leak', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 20,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'cost': 1.5,
            'noise': 0.6,
            'value': 0.6,
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
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-9798',
            'https://blog.fuzzing-project.org/60-Optionsbleed-HTTP-OPTIONS-method-can-leak-Apache-HTTPs-server-memory.html',
        ],
        'cve': 'CVE-2017-9798',
    }

    attempts = OptInteger(25, 'Number of OPTIONS probes', required=False, advanced=True)

    def run(self):
        n = max(5, min(int(self.attempts or 25), 100))
        for _ in range(n):
            r = self.http_request(method='OPTIONS', path='/', allow_redirects=False)
            if not r:
                continue
            if r.status_code == 405:
                return False
            allow = r.headers.get('Allow') or r.headers.get('allow') or ''
            if not allow:
                continue
            if re.search(r'(,{2,}|,\W+,|^\s*,|[0-9])', allow):
                self.set_info(
                    severity='medium',
                    reason=f'Optionsbleed-like Allow header: {allow[:120]}',
                    path='/',
                )
                return True
        return False
