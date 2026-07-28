#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Accela Civic Platform through 21."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Accela Civic Platform <=21.1 - Cross-Site Scripting Detection',
        'description': 'Accela Civic Platform through 21.1 contains a cross-site scripting vulnerability via ssoAdapter/logoutAction.do successURL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'redirect', 'accela', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/49990',
            'https://www.accela.com/civic-platform/',
            'https://gist.github.com/0xx7/7e9f1b725f7ff98b9239d3cb027b7dc8',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-34370',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-34370',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ssoAdapter/logoutAction.do?servProvCode=SAFVC&successURL=https://interact.sh/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Accela Civic Platform <=21.1 - Cross-Site Scripting detected",
                path='/ssoAdapter/logoutAction.do?servProvCode=SAFVC&successURL=https://interact.sh/',
            )
            return True
        return False

