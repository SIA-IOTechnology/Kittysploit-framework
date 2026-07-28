#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Directory listing enabled."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Directory listing enabled Detection',
        'description': 'Detects Directory listing enabled.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misc', 'miscellaneous', 'generic', 'vuln'],
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': ['https://portswigger.net/kb/issues/00600100_directory-listing'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('directory listing for', 'index of /', '[to parent directory]', 'directory: /',)
        body_regexes = ('\\d{1,2}\\/\\d{1,2}\\/\\d{4}\\s+\\d+:\\d+\\s+[\\sAPM]+(&lt;dir&gt;|\\d+)\\s+<[Aa]\\s+[hH][rR][eE][fF]="\\/', '\\s+-\\s+\\/<\\/(title|h1)>',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, re.I) for rx in body_regexes)):
            self.set_info(
                severity='info',
                reason="Directory listing enabled detected",
                path='/',
            )
            return True
        return False

