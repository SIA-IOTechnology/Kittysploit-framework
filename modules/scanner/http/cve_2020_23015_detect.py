#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OPNsense through 20."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OPNsense <=20.1.5 - Open Redirect Detection',
        'description': 'OPNsense through 20.1.5 contains an open redirect vulnerability via the url redirect parameter in the login page, which is not filtered. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'redirect', 'opnsense', 'vuln'],
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
            'https://github.com/opnsense/core/issues/4061',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-23015',
            'https://github.com/anonymous364872/Rapier_Tool',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2020-23015',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?url=http://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_]*\\.)?interact\\.sh(?:\\s*?)$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="OPNsense <=20.1.5 - Open Redirect detected",
                path='/?url=http://interact.sh',
            )
            return True
        return False

