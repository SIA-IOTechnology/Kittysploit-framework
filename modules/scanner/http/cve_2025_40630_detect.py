#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IceWarp Mail Server version 11."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp Mail Server ≤11.4.0 - Open Redirect Detection',
        'description': 'IceWarp Mail Server version 11.4.0 and below contains an open redirect vulnerability that allows attackers to redirect users to arbitrary external domains through malicious URLs.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'icewarp', 'redirect', 'open-redirect', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2025-40630',
            'https://www.incibe.es/en/incibe-cert/notices/aviso/multiple-vulnerabilities-icewarp-mail-server',
        ],
        'cve': 'CVE-2025-40630',
    }

    def run(self):
        r = self.http_request(method="GET", path='/%2f%5c%2foast.pro%2f..', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="IceWarp Mail Server ≤11.4.0 - Open Redirect detected",
                path='/%2f%5c%2foast.pro%2f..',
            )
            return True
        return False

