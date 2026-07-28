#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""u5cms version 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'u5cms v8.3.5 - Open Redirect Detection',
        'description': "u5cms version 8.3.5 contains a URL redirection vulnerability that can cause a user's browser to be redirected to another site via /loginsave.php.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'redirect', 'u5cms', 'cms', 'yuba', 'vuln'],
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
            'https://github.com/u5cms/u5cms/issues/50',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-32444',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Sharpforce/cybersecurity',
        ],
        'cve': 'CVE-2022-32444',
    }

    def run(self):
        r = self.http_request(method="GET", path='/loginsave.php?u=http://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="u5cms v8.3.5 - Open Redirect detected",
                path='/loginsave.php?u=http://interact.sh',
            )
            return True
        return False

