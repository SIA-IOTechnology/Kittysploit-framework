#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Babel contains an open redirect vulnerability via redirect."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Babel - Open Redirect Detection',
        'description': 'Babel contains an open redirect vulnerability via redirect.php in the newurl parameter. An attacker can use any legitimate site using Babel to redirect user to a malicious site, thus possibly obtaining sensitive information, modifying data, and/or executing unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'redirect', 'babel', 'cmsmadesimple', 'vuln'],
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
            'https://untrustednetwork.net/en/2019/02/20/open-redirection-vulnerability-in-babel/',
            'http://dev.cmsmadesimple.org/project/files/729',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-1010290',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-1010290',
    }

    def run(self):
        r = self.http_request(method="GET", path='/modules/babel/redirect.php?newurl=http://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Babel - Open Redirect detected",
                path='/modules/babel/redirect.php?newurl=http://interact.sh',
            )
            return True
        return False

