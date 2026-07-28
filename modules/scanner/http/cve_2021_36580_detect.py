#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IceWarp Mail Server contains an open redirect via the referer parameter."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp Mail Server - Open Redirect Detection',
        'description': 'IceWarp Mail Server contains an open redirect via the referer parameter. This can lead to phishing attacks or other unintended redirects.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'icewarp', 'redirect', 'vuln'],
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
            'https://www.icewarp.com/',
            'https://twitter.com/shifacyclewala/status/1443298941311668227',
            'http://icewarp.com',
            'http://mail.ziyan.com',
            'https://medium.com/%40rohitgautam26/cve-2021-36580-69219798231c',
        ],
        'cve': 'CVE-2021-36580',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webmail/basic/?referer=https://interact.sh&_c=auth&ctz=120&signup_password=&_a%5bsignup%5d=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="IceWarp Mail Server - Open Redirect detected",
                path='/webmail/basic/?referer=https://interact.sh&_c=auth&ctz=120&signup_password=&_a%5bsignup%5d=1',
            )
            return True
        return False

