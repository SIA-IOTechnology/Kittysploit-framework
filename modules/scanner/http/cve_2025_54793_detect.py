#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Astro 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Astro SSR - Open Redirect Detection',
        'description': 'Astro 5.2.0 through 5.12.7 contains an open redirect caused by improper handling of paths with double slashes in trailing slash redirection logic, letting attackers redirect users to arbitrary external domains, exploit requires on-demand SSR with Node or Cloudflare adapters.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'astro', 'redirect', 'open-redirect'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://github.com/withastro/astro/security/advisories/GHSA-cq8c-xv66-36gw',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-54793',
            'https://github.com/withastro/astro/commit/9ec88a04f93611cc07deff76ef6a18c88d6a77b9',
        ],
        'cve': 'CVE-2025-54793',
    }

    def run(self):
        for path in ('//interact.sh/en//', '//interact.sh/en/', '//interact.sh/en'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (301, 302, 307, 308):
                continue
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_regexes = ('(?i)location:\\s*//interact\\.sh',)
            if (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Astro SSR - Open Redirect detected",
                    path=path,
                )
                return True
        return False

