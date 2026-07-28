#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An open redirect vulnerability exists in the gradio-app/gradio, affecting the latest version."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gradio - Open Redirect Detection',
        'description': 'An open redirect vulnerability exists in the gradio-app/gradio, affecting the latest version. The vulnerability allows an attacker to redirect users to arbitrary websites, which can be exploited for phishing attacks, Cross-site Scripting (XSS), Server-Side Request Forgery (SSRF), amongst others. This issue is due to improper validation of user-supplied input in the handling of URLs. Attackers can exploit this vulnerability by crafting a malicious URL that, when processed by the application, redirects the user to an attacker-controlled web page.',
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
        'references': ['https://huntr.com/bounties/35aaea93-6895-4f03-9c1b-cd992665aa60'],
        'cve': 'CVE-2024-4940',
    }

    def run(self):
        path = '/file=http://oast.pro/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro.*$',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(severity='medium', reason='Gradio - Open Redirect detected', path=path)
            return True
        return False

