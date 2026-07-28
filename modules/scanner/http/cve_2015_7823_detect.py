#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kentico CMS 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kentico CMS 8.2 - Open Redirect Detection',
        'description': 'Kentico CMS 8.2 contains an open redirect vulnerability via GetDocLink.ashx with link variable. An attacker can construct a URL within the application that causes a redirection to an arbitrary external domain.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'kentico', 'redirect', 'packetstorm', 'vuln'],
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
            'https://packetstormsecurity.com/files/133981/Kentico-CMS-8.2-Cross-Site-Scripting-Open-Redirect.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-7823',
            'http://packetstormsecurity.com/files/133981/Kentico-CMS-8.2-Cross-Site-Scripting-Open-Redirect.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-7823',
    }

    def run(self):
        r = self.http_request(method="GET", path='/CMSPages/GetDocLink.ashx?link=https://interact.sh/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Kentico CMS 8.2 - Open Redirect detected",
                path='/CMSPages/GetDocLink.ashx?link=https://interact.sh/',
            )
            return True
        return False

