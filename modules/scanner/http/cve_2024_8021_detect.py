#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gradio allows an open redirect bypass via URL encoding, enabling attackers to redirect users to malicious site."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gradio - Open Redirect Detection',
        'description': 'Gradio allows an open redirect bypass via URL encoding, enabling attackers to redirect users to malicious sites. This can lead to phishing attacks and loss of trust in the application.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'redirect', 'oast', 'gradio', 'vuln'],
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
        'references': ['https://huntr.com/bounties/adc23067-ec04-47ef-9265-afd452071888'],
        'cve': 'CVE-2024-8021',
    }

    def run(self):
        path = '/file=http%3A%2F%2Foast.pro/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro.*$',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(severity='medium', reason='Gradio - Open Redirect detected', path=path)
            return True
        return False

