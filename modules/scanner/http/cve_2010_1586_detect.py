#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open redirect vulnerability in red2301."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HP System Management Homepage (SMH) v2.x.x.x - Open Redirect Detection',
        'description': 'Open redirect vulnerability in red2301.html in HP System Management Homepage (SMH) 2.x.x.x allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via the RedirectUrl parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'redirect', 'smh', 'hp', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-1586',
            'https://yehg.net/lab/pr0js/advisories/hp_system_management_homepage_url_redirection_abuse',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/58107',
        ],
        'cve': 'CVE-2010-1586',
    }

    def run(self):
        r = self.http_request(method="GET", path='/red2301.html?RedirectUrl=http://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:http?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="HP System Management Homepage (SMH) v2.x.x.x - Open Redirect detected",
                path='/red2301.html?RedirectUrl=http://interact.sh',
            )
            return True
        return False

