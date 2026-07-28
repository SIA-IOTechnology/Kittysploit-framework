#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Caddy 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Caddy 2.4.6 - Open Redirect Detection',
        'description': 'Caddy 2.4.6 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site via a crafted URL and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'redirect', 'caddy', 'webserver', 'caddyserver', 'vuln'],
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
            'https://lednerb.de/en/publications/responsible-disclosure/caddy-open-redirect-vulnerability/',
            'https://www.cve.org/CVERecord?id=CVE-2022-28923',
            'https://github.com/caddyserver/caddy/issues/4502',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-28923',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-28923',
    }

    def run(self):
        r = self.http_request(method="GET", path='/%5C%5Cinteract.sh/%252e%252e%252f', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Caddy 2.4.6 - Open Redirect detected",
                path='/%5C%5Cinteract.sh/%252e%252e%252f',
            )
            return True
        return False

