#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hoppscotch <= 2026."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hoppscotch <= 2026.2.1 - Open Redirect Detection',
        'description': 'Hoppscotch <= 2026.2.1 is vulnerable to a DOM-based open redirect on the /enter page. The redirect query parameter is passed directly to windowz location.href with no origin validation. Requires one additional query parameter to trigger. Exploited via a crafted URL such as /enter?redirect=evil.com&foo=bar.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'hoppscotch', 'redirect'],
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
            'https://github.com/hoppscotch/hoppscotch/security/advisories/GHSA-27pm-c9ch-746q',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-34847',
        ],
        'cve': 'CVE-2026-34847',
    }

    def run(self):
        r = self.http_request(method="GET", path='/enter?redirect=oast.me&foo=bar', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.me\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Hoppscotch <= 2026.2.1 - Open Redirect detected",
                path='/enter?redirect=oast.me&foo=bar',
            )
            return True
        return False

