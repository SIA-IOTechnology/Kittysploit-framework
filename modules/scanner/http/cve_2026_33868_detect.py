#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mastodon version < 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mastodon - Open Redirect Detection',
        'description': 'Mastodon version < 4.5.8, < 4.4.15, < 4.3.21 is vulnerable to unauthenticated Open Redirect vulnerability (CWE-601) exists in the /web/* route due to improper handling of URL-encoded path segments.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'mastodon', 'open-redirect', 'vuln', 'unauth'],
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
            'https://github.com/mastodon/mastodon/security/advisories/GHSA-xqw8-4j56-5hj6',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-33868',
        ],
        'cve': 'CVE-2026-33868',
    }

    def run(self):
        r = self.http_request(method="GET", path='/web/%2Finteract.sh:443', allow_redirects=False)
        if not r or r.status_code not in (302, 301):
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Mastodon - Open Redirect detected",
                path='/web/%2Finteract.sh:443',
            )
            return True
        return False

