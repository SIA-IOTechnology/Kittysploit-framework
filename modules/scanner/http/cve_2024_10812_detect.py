#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An open redirect vulnerability exists in GPT Academic v1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GPT Academic v1.3.9 - Open Redirect Detection',
        'description': 'An open redirect vulnerability exists in GPT Academic v1.3.9, where the file parameter in the /file= endpoint can be manipulated to redirect users to malicious websites. This could facilitate phishing attacks by tricking users into visiting attacker-controlled URLs.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'huntr', 'redirect', 'oss', 'gpt_academic', 'binary-husky', 'vuln'],
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
        'references': ['https://huntr.com/bounties/51408ebd-e0be-489d-8088-f210087dbd6a'],
        'cve': 'CVE-2024-10812',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/file=https://oast.pro'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro.*$',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(severity='medium', reason='GPT Academic v1.3.9 - Open Redirect detected', path=path)
            return True
        return False

