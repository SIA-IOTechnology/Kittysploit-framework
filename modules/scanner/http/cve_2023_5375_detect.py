#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open Redirect in GitHub repository mosparo/mosparo prior to 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mosparo < 1.0.2 - Open Redirect Detection',
        'description': 'Open Redirect in GitHub repository mosparo/mosparo prior to 1.0.2.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'huntr', 'mosparo', 'redirect', 'vuln'],
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
            'https://huntr.dev/bounties/3fa2abde-cb58-45a3-a115-1727ece9acb9',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-5375',
            'https://github.com/mosparo/mosparo/commit/9d5da367b78b8c883bfef5f332ffea26292f99e8',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
        ],
        'cve': 'CVE-2023-5375',
    }

    def run(self):
        r = self.http_request(method="GET", path='/project/switch/1?targetPath=http://oast.pro', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Mosparo < 1.0.2 - Open Redirect detected",
                path='/project/switch/1?targetPath=http://oast.pro',
            )
            return True
        return False

