#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""postMessage contains a cross-site scripting vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'postMessage - Cross-Site Scripting Detection',
        'description': 'postMessage contains a cross-site scripting vulnerability. An attacker can execute arbitrary script and therefore steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'xss', 'postmessage', 'misconfig', 'vuln'],
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
        'references': [
            'https://jlajara.gitlab.io/web/2020/06/12/Dom_XSS_PostMessage.html',
            'https://payatu.com/blog/anubhav.singh/postmessage-vulnerabilities',
            'https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('postMessage\\([a-zA-Z]+,["\']\\*["\']\\)',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='info',
                reason="postMessage - Cross-Site Scripting detected",
                path='/',
            )
            return True
        return False

