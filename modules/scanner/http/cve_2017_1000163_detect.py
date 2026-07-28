#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phoenix Framework versions 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Phoenix Framework - Open Redirect Detection',
        'description': 'Phoenix Framework versions 1.0.0 through 1.0.4, 1.1.0 through 1.1.6, 1.2.0, 1.2.2 and 1.3.0-rc.0 contain an open redirect vulnerability, which may result in phishing or social engineering attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'redirect', 'phoenix', 'phoenixframework', 'vuln'],
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
            'https://elixirforum.com/t/security-releases-for-phoenix/4143',
            'https://vuldb.com/?id.109587',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-1000163',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2017-1000163',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?redirect=/\\interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_]*\\.)?interact\\.sh(?:\\s*?)$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Phoenix Framework - Open Redirect detected",
                path='/?redirect=/\\interact.sh',
            )
            return True
        return False

