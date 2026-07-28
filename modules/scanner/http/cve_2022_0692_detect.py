#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An open redirect vulnerability exists in Rudloff/alltube that could let an attacker construct a URL within the."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Rudloff alltube prior to 3.0.1 - Open Redirect Detection',
        'description': 'An open redirect vulnerability exists in Rudloff/alltube that could let an attacker construct a URL within the application that causes redirection to an arbitrary external domain via Packagist in versions prior to 3.0.1.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'huntr', 'redirect', 'rudloff', 'alltube', 'alltube_project', 'vuln'],
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
            'https://huntr.dev/bounties/4fb39400-e08b-47af-8c1f-5093c9a51203/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0692',
            'https://huntr.dev/bounties/4fb39400-e08b-47af-8c1f-5093c9a51203',
            'https://github.com/rudloff/alltube/commit/bc14b6e45c766c05757fb607ef8d444cbbfba71a',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-0692',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php/interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Rudloff alltube prior to 3.0.1 - Open Redirect detected",
                path='/index.php/interact.sh',
            )
            return True
        return False

