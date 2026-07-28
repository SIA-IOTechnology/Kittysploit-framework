#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple Open Redirect in GitHub repository nitely/spirit prior to 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'nitely/spirit 0.12.3 - Open Redirect Detection',
        'description': 'Multiple Open Redirect in GitHub repository nitely/spirit prior to 0.12.3.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'huntr', 'redirect', 'nitely', 'spirit', 'spirit-project', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0869',
            'https://huntr.dev/bounties/ed335a88-f68c-4e4d-ac85-f29a51b03342',
            'https://github.com/nitely/spirit/commit/8f32f89654d6c30d56e0dd167059d32146fb32ef',
        ],
        'cve': 'CVE-2022-0869',
    }

    def run(self):
        for path in ('/user/login/?next=https%3A%2F%2Finteract.sh', '/user/logout?next=https%3A%2F%2Finteract.sh', '/user/register?next=https%3A%2F%2Finteract.sh', '/user/resend-activation?next=https%3A%2F%2Finteract.sh'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
            if (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='medium',
                    reason="nitely/spirit 0.12.3 - Open Redirect detected",
                    path=path,
                )
                return True
        return False

