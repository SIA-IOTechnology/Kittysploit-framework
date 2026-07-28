#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki Platform is vulnerable to open redirect attacks due to improper validation of the xredirect parameter."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki - Open Redirect Detection',
        'description': 'XWiki Platform is vulnerable to open redirect attacks due to improper validation of the xredirect parameter. This allows an attacker to redirect users to an arbitrary website. The vulnerability is patched in versions 14.10.4 and 15.0.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xwiki', 'redirect', 'vuln'],
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
        'references': ['https://jira.xwiki.org/browse/XWIKI-20096', 'https://nvd.nist.gov/vuln/detail/CVE-2023-32068'],
        'cve': 'CVE-2023-32068',
    }

    def run(self):
        r = self.http_request(method="GET", path='/bin/login/XWiki/XWikiLogin?xredirect=//oast.me', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_]*\\.)?oast\\.me(?:\\s*?)$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="XWiki - Open Redirect detected",
                path='/bin/login/XWiki/XWikiLogin?xredirect=//oast.me',
            )
            return True
        return False

