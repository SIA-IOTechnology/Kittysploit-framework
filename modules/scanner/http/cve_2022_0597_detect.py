#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open Redirect in Packagist microweber/microweber prior to 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microweber < 1.2.11 - Open Redirection Detection',
        'description': 'Open Redirect in Packagist microweber/microweber prior to 1.2.11.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'huntr', 'microweber', 'redirect', 'oss', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0597',
            'https://huntr.dev/bounties/68c22eab-cc69-4e9f-bcb6-2df3db626813/',
            'https://www.mend.io/vulnerability-database/CVE-2022-0597',
            'https://github.com/microweber/microweber/commit/acfc6a581d1ea86096d1b0ecd8a0eec927c0e9b2',
        ],
        'cve': 'CVE-2022-0597',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/logout?redirect_to=http://oast.pro/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Microweber < 1.2.11 - Open Redirection detected",
                path='/api/logout?redirect_to=http://oast.pro/',
            )
            return True
        return False

